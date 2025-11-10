#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown, clippy::if_not_else, clippy::non_ascii_literal)]

use rustscan::benchmark::{Benchmark, NamedTimer};
use rustscan::input::Opts;
use rustscan::port_strategy::PortStrategy;
use rustscan::scanner::Scanner;
use rustscan::{detail, funny_opening, warning};

use colorful::{Color, Colorful};
use futures::executor::block_on;
use std::collections::HashMap;
use std::net::IpAddr;
use std::string::ToString;
use std::time::Duration;

use rustscan::address::parse_addresses;

extern crate colorful;

// Average value for Ubuntu
#[cfg(unix)]
const DEFAULT_FILE_DESCRIPTORS_LIMIT: u64 = 8000;
// Safest batch size based on experimentation
const AVERAGE_BATCH_SIZE: u16 = 3000;

#[macro_use]
extern crate log;

#[cfg(not(tarpaulin_include))]
#[allow(clippy::too_many_lines)]
/// Faster Nmap scanning with Rust
/// If you're looking for the actual scanning, check out the module Scanner
fn main() {
    #[cfg(not(unix))]
    let _ = ansi_term::enable_ansi_support();

    env_logger::init();
    let mut benchmarks = Benchmark::init();
    let mut rustscan_bench = NamedTimer::start("RustScan主流程");

    let opts: Opts = Opts::read();

    debug!("Main() `opts` arguments are {opts:?}");

    if !opts.greppable && !opts.accessible && !opts.no_banner {
        print_opening();
    }

    let ips: Vec<IpAddr> = parse_addresses(&opts);

    if ips.is_empty() {
        warning!(
            "未能解析任何 IP，扫描已终止。",
            opts.greppable,
            opts.accessible
        );
        std::process::exit(1);
    }

    #[cfg(unix)]
    let batch_size: u16 = infer_batch_size(&opts, adjust_ulimit_size(&opts));

    #[cfg(not(unix))]
    let batch_size: u16 = AVERAGE_BATCH_SIZE;

    let scanner = Scanner::new(
        &ips,
        batch_size,
        Duration::from_millis(opts.timeout.into()),
        opts.tries,
        opts.greppable,
        PortStrategy::pick(&opts.ports, opts.scan_order),
        opts.accessible,
        opts.exclude_ports.unwrap_or_default(),
        opts.udp,
    );
    debug!("Scanner finished building: {scanner:?}");

    let mut portscan_bench = NamedTimer::start("端口扫描");
    let scan_result = block_on(scanner.run());
    portscan_bench.end();
    benchmarks.push(portscan_bench);

    let mut ports_per_ip = HashMap::new();

    for socket in scan_result {
        ports_per_ip
            .entry(socket.ip())
            .or_insert_with(Vec::new)
            .push(socket.port());
    }

    for ports in ports_per_ip.values_mut() {
        ports.sort_unstable();
    }

    for ip in ips {
        if ports_per_ip.contains_key(&ip) {
            continue;
        }

        // If we got here it means the IP was not found within the HashMap, this
        // means the scan couldn't find any open ports for it.

        let x = format!(
            "未能在 {:?} 上发现开放端口，这通常是批量大小过大的结果。
        \n* 当前批量大小为 {}，请使用 {} 或根据系统情况调小。
        \n 如果网络时延较高，也可以通过 'rustscan -t 2000' 将超时时间提升到 2000 毫秒（2 秒）。\n",
            ip, opts.batch_size, "'rustscan -b <批量大小> -a <IP 地址>'"
        );
        warning!(x, opts.greppable, opts.accessible);
    }

    let mut reporting_bench = NamedTimer::start("结果汇总");
    for (ip, ports) in &ports_per_ip {
        let vec_str_ports: Vec<String> = ports.iter().map(ToString::to_string).collect();

        // Ports are printed as 80,443 (comma separated without spaces).
        let ports_str = vec_str_ports.join(",");
        let open_count = ports.len();

        if opts.greppable {
            println!("{} -> [{}]", &ip, ports_str);
            println!("开放端口总数: {open_count}");
            continue;
        }

        let message = format!("[~] {ip} 的开放端口: [{ports_str}]");
        detail!(message, opts.greppable, opts.accessible);

        let summary_message = format!("开放端口总数: {open_count}");
        if opts.accessible {
            println!("{summary_message}");
        } else {
            println!("{}", summary_message.cyan());
        }
    }

    // To use the runtime benchmark, run the process as: RUST_LOG=info ./rustscan
    reporting_bench.end();
    benchmarks.push(reporting_bench);
    rustscan_bench.end();
    benchmarks.push(rustscan_bench);
    debug!("Benchmarks raw {benchmarks:?}");
    info!("{}", benchmarks.summary());
}

/// Prints the opening title of RustScan
#[allow(clippy::items_after_statements, clippy::needless_raw_string_hashes)]
fn print_opening() {
    debug!("Printing opening");
    let s = r#".----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
"#;

    println!("{}", s.gradient(Color::Green).bold());
    funny_opening!();
}

#[cfg(unix)]
fn adjust_ulimit_size(opts: &Opts) -> u64 {
    use rlimit::Resource;

    if let Some(limit) = opts.ulimit {
        if Resource::NOFILE.set(limit, limit).is_ok() {
            detail!(
                format!("已自动将 ulimit 调整为 {limit}。"),
                opts.greppable,
                opts.accessible
            );
        } else {
            warning!("错误：无法设置 ulimit。", opts.greppable, opts.accessible);
        }
    }

    let (soft, _) = Resource::NOFILE.get().unwrap();
    soft
}

#[cfg(unix)]
fn infer_batch_size(opts: &Opts, ulimit: u64) -> u16 {
    use std::convert::TryInto;

    let mut batch_size: u64 = opts.batch_size.into();

    // Adjust the batch size when the ulimit value is lower than the desired batch size
    if ulimit < batch_size {
        warning!(
            "文件句柄上限低于默认批量大小，请使用 --ulimit 提升限制。否则可能影响敏感服务器。",
            opts.greppable,
            opts.accessible
        );

        // When the OS supports high file limits like 8000, but the user
        // selected a batch size higher than this we should reduce it to
        // a lower number.
        if ulimit < AVERAGE_BATCH_SIZE.into() {
            // ulimit is smaller than aveage batch size
            // user must have very small ulimit
            // decrease batch size to half of ulimit
            warning!("当前文件句柄上限过小，会显著降低 RustScan 的速度。请改用 Docker 镜像，或执行 '--ulimit 5000' 提升限制。 ", opts.greppable, opts.accessible);
            info!("由于 ulimit 低于推荐值，批量大小已减半");
            batch_size = ulimit / 2;
        } else if ulimit > DEFAULT_FILE_DESCRIPTORS_LIMIT {
            info!("批量大小已调整为推荐值");
            batch_size = AVERAGE_BATCH_SIZE.into();
        } else {
            batch_size = ulimit - 100;
        }
    }
    // When the ulimit is higher than the batch size let the user know that the
    // batch size can be increased unless they specified the ulimit themselves.
    else if ulimit + 2 > batch_size && (opts.ulimit.is_none()) {
        detail!(
            format!(
                "文件句柄上限高于当前批量大小，可通过 '-b {}' 提升扫描速度。",
                ulimit - 100
            ),
            opts.greppable,
            opts.accessible
        );
    }

    batch_size.try_into().expect("批量大小无法转换为 u16。")
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::{adjust_ulimit_size, infer_batch_size};
    use super::{print_opening, Opts};

    #[test]
    #[cfg(unix)]
    fn batch_size_lowered() {
        let opts = Opts {
            batch_size: 50_000,
            ..Default::default()
        };
        let batch_size = infer_batch_size(&opts, 120);

        assert!(batch_size < opts.batch_size);
    }

    #[test]
    #[cfg(unix)]
    fn batch_size_lowered_average_size() {
        let opts = Opts {
            batch_size: 50_000,
            ..Default::default()
        };
        let batch_size = infer_batch_size(&opts, 9_000);

        assert!(batch_size == 3_000);
    }
    #[test]
    #[cfg(unix)]
    fn batch_size_equals_ulimit_lowered() {
        // because ulimit and batch size are same size, batch size is lowered
        // to ULIMIT - 100
        let opts = Opts {
            batch_size: 50_000,
            ..Default::default()
        };
        let batch_size = infer_batch_size(&opts, 5_000);

        assert!(batch_size == 4_900);
    }
    #[test]
    #[cfg(unix)]
    fn batch_size_adjusted_2000() {
        // ulimit == batch_size
        let opts = Opts {
            batch_size: 50_000,
            ulimit: Some(2_000),
            ..Default::default()
        };
        let batch_size = adjust_ulimit_size(&opts);

        assert!(batch_size == 2_000);
    }

    #[test]
    #[cfg(unix)]
    fn test_high_ulimit_no_greppable_mode() {
        let opts = Opts {
            batch_size: 10,
            greppable: false,
            ..Default::default()
        };

        let batch_size = infer_batch_size(&opts, 1_000_000);

        assert!(batch_size == opts.batch_size);
    }

    #[test]
    fn test_print_opening_no_panic() {
        // print opening should not panic
        print_opening();
    }
}
