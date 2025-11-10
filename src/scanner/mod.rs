//! Core functionality for actual scanning behaviour.
use crate::detail;
use crate::generated::get_parsed_data;
use crate::port_strategy::PortStrategy;
use log::debug;

mod socket_iterator;
use socket_iterator::SocketIterator;

use async_std::net::TcpStream;
use async_std::prelude::*;
use async_std::{io, net::UdpSocket};
use colored::Colorize;
use futures::stream::FuturesUnordered;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::{
    collections::HashSet,
    net::{IpAddr, Shutdown, SocketAddr},
    num::NonZeroU8,
    time::{Duration, Instant},
};

/// The class for the scanner
/// IP is data type IpAddr and is the IP address
/// start & end is where the port scan starts and ends
/// batch_size is how many ports at a time should be scanned
/// Timeout is the time RustScan should wait before declaring a port closed. As datatype Duration.
/// greppable is whether or not RustScan should print things, or wait until the end to print only the ip and open ports.
#[cfg(not(tarpaulin_include))]
#[derive(Debug)]
pub struct Scanner {
    ips: Vec<IpAddr>,
    batch_size: u16,
    timeout: Duration,
    tries: NonZeroU8,
    greppable: bool,
    port_strategy: PortStrategy,
    accessible: bool,
    exclude_ports: Vec<u16>,
    udp: bool,
    timeout_overrides: Arc<RwLock<HashMap<IpAddr, Duration>>>,
}

// Allowing too many arguments for clippy.
#[allow(clippy::too_many_arguments)]
impl Scanner {
    pub fn new(
        ips: &[IpAddr],
        batch_size: u16,
        timeout: Duration,
        tries: u8,
        greppable: bool,
        port_strategy: PortStrategy,
        accessible: bool,
        exclude_ports: Vec<u16>,
        udp: bool,
    ) -> Self {
        Self {
            batch_size,
            timeout,
            tries: NonZeroU8::new(std::cmp::max(tries, 1)).unwrap(),
            greppable,
            port_strategy,
            ips: ips.iter().map(ToOwned::to_owned).collect(),
            accessible,
            exclude_ports,
            udp,
            timeout_overrides: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn current_timeout_for(&self, ip: IpAddr) -> Duration {
        if let Ok(overrides) = self.timeout_overrides.read() {
            if let Some(timeout) = overrides.get(&ip) {
                return *timeout;
            }
        }
        self.timeout
    }

    fn has_timeout_override(&self, ip: IpAddr) -> bool {
        self.timeout_overrides
            .read()
            .map(|overrides| overrides.contains_key(&ip))
            .unwrap_or(false)
    }

    fn update_timeout_after_success(&self, ip: IpAddr, latency: Duration) {
        if let Ok(mut overrides) = self.timeout_overrides.write() {
            if overrides.contains_key(&ip) {
                return;
            }

            let previous_timeout = self.timeout;
            let scaled_secs = (latency.as_secs_f64() * 2.2_f64).max(0.001);
            let adjusted_timeout = Duration::from_secs_f64(scaled_secs);

            overrides.insert(ip, adjusted_timeout);

            let from_ms = previous_timeout.as_secs_f64() * 1000.0;
            let to_ms = adjusted_timeout.as_secs_f64() * 1000.0;
            let message = format!("强化介入 IP {ip} 延迟从 {from_ms:.2} 优化至 {to_ms:.2} 毫秒");
            detail!(message, self.greppable, self.accessible);
        }
    }

    /// Runs scan_range with chunk sizes
    /// If you want to run RustScan normally, this is the entry point used
    /// Returns all open ports as `Vec<u16>`
    pub async fn run(&self) -> Vec<SocketAddr> {
        let ports: Vec<u16> = self
            .port_strategy
            .order()
            .iter()
            .filter(|&port| !self.exclude_ports.contains(port))
            .copied()
            .collect();
        let mut socket_iterator: SocketIterator = SocketIterator::new(&self.ips, &ports);
        let mut open_sockets: Vec<SocketAddr> = Vec::new();
        let mut ftrs: FuturesUnordered<_> = FuturesUnordered::new();
        let mut errors: HashSet<String> = HashSet::new();
        let udp_map = get_parsed_data();
        let mut deferred: VecDeque<SocketAddr> = VecDeque::new();
        let mut inflight_without_override: HashMap<IpAddr, usize> = HashMap::new();

        'initial_fill: while ftrs.len() < self.batch_size as usize {
            let mut scheduled = false;
            let attempts = deferred.len() + 1;
            for _ in 0..attempts {
                let next_socket = if let Some(socket) = deferred.pop_front() {
                    Some(socket)
                } else {
                    socket_iterator.next()
                };

                let Some(socket) = next_socket else {
                    break 'initial_fill;
                };

                let ip = socket.ip();
                if !self.has_timeout_override(ip) {
                    let entry = inflight_without_override.entry(ip).or_insert(0);
                    if *entry >= 1 {
                        deferred.push_back(socket);
                        continue;
                    }
                    *entry += 1;
                }

                ftrs.push(self.spawn_scan_task(socket, udp_map.clone()));
                scheduled = true;
                break;
            }

            if !scheduled {
                break;
            }
        }

        debug!("Start scanning sockets. \nBatch size {}\nNumber of ip-s {}\nNumber of ports {}\nTargets all together {} ",
            self.batch_size,
            self.ips.len(),
            &ports.len(),
            (self.ips.len() * ports.len()));

        while let Some((ip, result)) = ftrs.next().await {
            let mut remove_entry = false;
            if let Some(count) = inflight_without_override.get_mut(&ip) {
                if *count > 0 {
                    *count -= 1;
                }
                if *count == 0 {
                    remove_entry = true;
                }
            }
            if remove_entry {
                inflight_without_override.remove(&ip);
            }

            match result {
                Ok(socket) => open_sockets.push(socket),
                Err(e) => {
                    let error_string = e.to_string();
                    if errors.len() < self.ips.len() * 1000 {
                        errors.insert(error_string);
                    }
                }
            }

            'refill: while ftrs.len() < self.batch_size as usize {
                let mut scheduled = false;
                let attempts = deferred.len() + 1;
                for _ in 0..attempts {
                    let next_socket = if let Some(socket) = deferred.pop_front() {
                        Some(socket)
                    } else {
                        socket_iterator.next()
                    };

                    let Some(socket) = next_socket else {
                        break 'refill;
                    };

                    let candidate_ip = socket.ip();
                    if !self.has_timeout_override(candidate_ip) {
                        let entry = inflight_without_override.entry(candidate_ip).or_insert(0);
                        if *entry >= 1 {
                            deferred.push_back(socket);
                            continue;
                        }
                        *entry += 1;
                    }

                    ftrs.push(self.spawn_scan_task(socket, udp_map.clone()));
                    scheduled = true;
                    break;
                }

                if !scheduled {
                    break;
                }
            }
        }
        debug!("Typical socket connection errors {errors:?}");
        debug!("Open Sockets found: {:?}", &open_sockets);
        open_sockets
    }

    /// Given a socket, scan it self.tries times.
    /// Turns the address into a SocketAddr
    /// Deals with the `<result>` type
    /// If it experiences error ErrorKind::Other then too many files are open and it Panics!
    /// Else any other error, it returns the error in Result as a string
    /// If no errors occur, it returns the port number in Result to signify the port is open.
    /// This function mainly deals with the logic of Results handling.
    /// # Example
    ///
    /// ```compile_fail
    /// scanner.scan_socket(socket)
    /// ```
    ///
    /// Note: `self` must contain `self.ip`.
    fn spawn_scan_task(
        &self,
        socket: SocketAddr,
        udp_map: BTreeMap<Vec<u16>, Vec<u8>>,
    ) -> impl std::future::Future<Output = (IpAddr, io::Result<SocketAddr>)> + '_ {
        let ip = socket.ip();
        async move {
            let result = self.scan_socket(socket, udp_map).await;
            (ip, result)
        }
    }

    async fn scan_socket(
        &self,
        socket: SocketAddr,
        udp_map: BTreeMap<Vec<u16>, Vec<u8>>,
    ) -> io::Result<SocketAddr> {
        if self.udp {
            return self.scan_udp_socket(socket, udp_map).await;
        }

        let tries = self.tries.get();
        for nr_try in 1..=tries {
            match self.connect(socket).await {
                Ok((tcp_stream, latency)) => {
                    debug!(
                        "Connection was successful, shutting down stream {}",
                        &socket
                    );
                    if let Err(e) = tcp_stream.shutdown(Shutdown::Both) {
                        debug!("Shutdown stream error {}", &e);
                    }
                    self.fmt_ports(socket, latency);
                    self.update_timeout_after_success(socket.ip(), latency);

                    debug!("Return Ok after {nr_try} tries");
                    return Ok(socket);
                }
                Err(e) => {
                    let mut error_string = e.to_string();

                    assert!(!error_string.to_lowercase().contains("too many open files"), "Too many open files. Please reduce batch size. The default is 5000. Try -b 2500.");

                    if nr_try == tries {
                        error_string.push(' ');
                        error_string.push_str(&socket.ip().to_string());
                        return Err(io::Error::other(error_string));
                    }
                }
            };
        }
        unreachable!();
    }

    async fn scan_udp_socket(
        &self,
        socket: SocketAddr,
        udp_map: BTreeMap<Vec<u16>, Vec<u8>>,
    ) -> io::Result<SocketAddr> {
        let mut payload: Vec<u8> = Vec::new();
        for (key, value) in udp_map {
            if key.contains(&socket.port()) {
                payload = value;
            }
        }

        let tries = self.tries.get();
        for _ in 1..=tries {
            let timeout = self.current_timeout_for(socket.ip());
            match self.udp_scan(socket, &payload, timeout).await {
                Ok(true) => return Ok(socket),
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
        }

        Err(io::Error::other(format!(
            "UDP scan timed-out for all tries on socket {socket}"
        )))
    }

    /// Performs the connection to the socket with timeout
    /// # Example
    ///
    /// ```compile_fail
    /// # use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    /// let port: u16 = 80;
    /// // ip is an IpAddr type
    /// let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    /// let socket = SocketAddr::new(ip, port);
    /// scanner.connect(socket);
    /// // returns Result which is either Ok((stream, latency)) for port is open, or Err for port is closed.
    /// // Timeout occurs after self.timeout seconds
    /// ```
    ///
    async fn connect(&self, socket: SocketAddr) -> io::Result<(TcpStream, Duration)> {
        let timeout = self.current_timeout_for(socket.ip());
        let start = Instant::now();
        let stream = io::timeout(timeout, async move { TcpStream::connect(socket).await }).await?;
        Ok((stream, start.elapsed()))
    }

    /// Binds to a UDP socket so we can send and receive packets
    /// # Example
    ///
    /// ```compile_fail
    /// # use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    /// let port: u16 = 80;
    /// // ip is an IpAddr type
    /// let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    /// let socket = SocketAddr::new(ip, port);
    /// scanner.udp_bind(socket);
    /// // returns Result which is either Ok(stream) for port is open, or Err for port is closed.
    /// // Timeout occurs after self.timeout seconds
    /// ```
    ///
    async fn udp_bind(&self, socket: SocketAddr) -> io::Result<UdpSocket> {
        let local_addr = match socket {
            SocketAddr::V4(_) => "0.0.0.0:0".parse::<SocketAddr>().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse::<SocketAddr>().unwrap(),
        };

        UdpSocket::bind(local_addr).await
    }

    /// Performs a UDP scan on the specified socket with a payload and wait duration
    /// # Example
    ///
    /// ```compile_fail
    /// # use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    /// # use std::time::Duration;
    /// let port: u16 = 123;
    /// // ip is an IpAddr type
    /// let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    /// let socket = SocketAddr::new(ip, port);
    /// let payload = vec![0, 1, 2, 3];
    /// let wait = Duration::from_secs(1);
    /// let result = scanner.udp_scan(socket, payload, wait).await;
    /// // returns Result which is either Ok(true) if response received, or Ok(false) if timed out.
    /// // Err is returned for other I/O errors.
    async fn udp_scan(
        &self,
        socket: SocketAddr,
        payload: &[u8],
        wait: Duration,
    ) -> io::Result<bool> {
        match self.udp_bind(socket).await {
            Ok(udp_socket) => {
                let mut buf = [0u8; 1024];

                udp_socket.connect(socket).await?;
                let start = Instant::now();
                udp_socket.send(payload).await?;

                match io::timeout(wait, udp_socket.recv(&mut buf)).await {
                    Ok(size) => {
                        debug!("Received {size} bytes");
                        let latency = start.elapsed();
                        self.fmt_ports(socket, latency);
                        self.update_timeout_after_success(socket.ip(), latency);
                        Ok(true)
                    }
                    Err(e) => {
                        if e.kind() == io::ErrorKind::TimedOut {
                            Ok(false)
                        } else {
                            Err(e)
                        }
                    }
                }
            }
            Err(e) => {
                println!("绑定套接字时出错 {e:?}");
                Err(e)
            }
        }
    }

    /// Formats and prints the port status
    fn fmt_ports(&self, socket: SocketAddr, latency: Duration) {
        let latency_ms = latency.as_secs_f64() * 1000.0;
        let latency_display = format!("{latency_ms:.2}");
        if !self.greppable {
            if self.accessible {
                println!("发现开放端口 {socket} 延迟 {latency_display}ms");
            } else {
                println!(
                    "发现开放端口 {} 延迟 {latency_display}ms",
                    socket.to_string().purple()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{PortRange, ScanOrder};
    use async_std::task::block_on;
    use std::{net::IpAddr, time::Duration};

    #[test]
    fn scanner_runs() {
        // Makes sure the program still runs and doesn't panic
        let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
        let range = PortRange {
            start: 1,
            end: 1_000,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            false,
        );
        block_on(scanner.run());
        // if the scan fails, it wouldn't be able to assert_eq! as it panicked!
        assert_eq!(1, 1);
    }
    #[test]
    fn ipv6_scanner_runs() {
        // Makes sure the program still runs and doesn't panic
        let addrs = vec!["::1".parse::<IpAddr>().unwrap()];
        let range = PortRange {
            start: 1,
            end: 1_000,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            false,
        );
        block_on(scanner.run());
        // if the scan fails, it wouldn't be able to assert_eq! as it panicked!
        assert_eq!(1, 1);
    }
    #[test]
    fn quad_zero_scanner_runs() {
        let addrs = vec!["0.0.0.0".parse::<IpAddr>().unwrap()];
        let range = PortRange {
            start: 1,
            end: 1_000,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            false,
        );
        block_on(scanner.run());
        assert_eq!(1, 1);
    }
    #[test]
    fn google_dns_runs() {
        let addrs = vec!["8.8.8.8".parse::<IpAddr>().unwrap()];
        let range = PortRange {
            start: 400,
            end: 445,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            false,
        );
        block_on(scanner.run());
        assert_eq!(1, 1);
    }
    #[test]
    fn infer_ulimit_lowering_no_panic() {
        // Test behaviour on MacOS where ulimit is not automatically lowered
        let addrs = vec!["8.8.8.8".parse::<IpAddr>().unwrap()];

        // mac should have this automatically scaled down
        let range = PortRange {
            start: 400,
            end: 600,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            false,
        );
        block_on(scanner.run());
        assert_eq!(1, 1);
    }

    #[test]
    fn udp_scan_runs() {
        // Makes sure the program still runs and doesn't panic
        let addrs = vec!["127.0.0.1".parse::<IpAddr>().unwrap()];
        let range = PortRange {
            start: 1,
            end: 1_000,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            true,
        );
        block_on(scanner.run());
        // if the scan fails, it wouldn't be able to assert_eq! as it panicked!
        assert_eq!(1, 1);
    }
    #[test]
    fn udp_ipv6_runs() {
        // Makes sure the program still runs and doesn't panic
        let addrs = vec!["::1".parse::<IpAddr>().unwrap()];
        let range = PortRange {
            start: 1,
            end: 1_000,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            true,
        );
        block_on(scanner.run());
        // if the scan fails, it wouldn't be able to assert_eq! as it panicked!
        assert_eq!(1, 1);
    }
    #[test]
    fn udp_quad_zero_scanner_runs() {
        let addrs = vec!["0.0.0.0".parse::<IpAddr>().unwrap()];
        let range = PortRange {
            start: 1,
            end: 1_000,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            true,
        );
        block_on(scanner.run());
        assert_eq!(1, 1);
    }
    #[test]
    fn udp_google_dns_runs() {
        let addrs = vec!["8.8.8.8".parse::<IpAddr>().unwrap()];
        let range = PortRange {
            start: 100,
            end: 150,
        };
        let strategy = PortStrategy::pick(&Some(range), None, ScanOrder::Random);
        let scanner = Scanner::new(
            &addrs,
            10,
            Duration::from_millis(100),
            1,
            true,
            strategy,
            true,
            vec![9000],
            true,
        );
        block_on(scanner.run());
        assert_eq!(1, 1);
    }
}
