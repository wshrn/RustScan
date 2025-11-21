#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown, clippy::if_not_else, clippy::non_ascii_literal)]

use rustscan::benchmark::{Benchmark, NamedTimer};
use rustscan::input::Opts;
use rustscan::port_strategy::PortStrategy;
use rustscan::scanner::{ProgressReporter, Scanner};
use rustscan::tui::{progress_println, register_progress_bar, ProgressBarGuard};
use rustscan::{detail, warning};

use colorful::{Color, Colorful};
use console::Term;
use encoding_rs::GB18030;
use futures::executor::block_on;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressFinish, ProgressStyle};
use native_tls::TlsConnector;
use once_cell::sync::OnceCell;
use rayon::ThreadPoolBuilder;
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{
    HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, CONNECTION, CONTENT_LENGTH, LOCATION,
    USER_AGENT,
};
use reqwest::redirect::Policy;
use reqwest::Url;
use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::string::ToString;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustscan::address::parse_addresses;

extern crate colorful;

// Average value for Ubuntu
#[cfg(unix)]
const DEFAULT_FILE_DESCRIPTORS_LIMIT: u64 = 8000;
// Safest batch size based on experimentation
const AVERAGE_BATCH_SIZE: u16 = 3000;
const PORTSCAN_PROGRESS_UPDATE_INTERVAL_SECS: u64 = 8;
const PORTSCAN_PROGRESS_DRAW_HZ: u8 = 1;
const HTTP_PROGRESS_DRAW_HZ: u8 = 10;

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
    let batch_size: u16 = opts.batch_size;

    let exclude_ports = opts.exclude_ports.clone().unwrap_or_default();
    let port_strategy = PortStrategy::pick(&opts.ports, opts.scan_order);
    let filtered_port_count = port_strategy
        .order()
        .into_iter()
        .filter(|port| !exclude_ports.contains(port))
        .count();
    let total_port_targets = filtered_port_count * ips.len();

    let mut scanner = Scanner::new(
        &ips,
        batch_size,
        Duration::from_millis(opts.timeout.into()),
        opts.tries,
        opts.greppable,
        port_strategy,
        opts.accessible,
        exclude_ports,
        opts.udp,
    );

    let mut portscan_progress_guard: Option<ProgressBarGuard> = None;
    let portscan_progress_bar = if total_port_targets > 0 && !opts.greppable {
        Some(create_progress_bar(
            total_port_targets as u64,
            "端口扫描进度",
            opts.accessible,
            PORTSCAN_PROGRESS_DRAW_HZ,
        ))
    } else {
        None
    };

    if let Some(progress_bar) = &portscan_progress_bar {
        portscan_progress_guard = Some(register_progress_bar(progress_bar));
    }

    if let Some(progress_bar) = &portscan_progress_bar {
        let progress_bar = progress_bar.clone();
        let update_interval = Duration::from_secs(PORTSCAN_PROGRESS_UPDATE_INTERVAL_SECS);
        let last_draw_time = Arc::new(Mutex::new(None::<Instant>));

        scanner.set_progress_reporter(ProgressReporter::new({
            let last_draw_time = Arc::clone(&last_draw_time);
            move |completed, total| {
                if total == 0 {
                    let now = Instant::now();
                    if let Ok(mut last) = last_draw_time.lock() {
                        if last
                            .map(|instant| now.duration_since(instant) >= update_interval)
                            .unwrap_or(true)
                        {
                            progress_bar.set_position(0);
                            *last = Some(now);
                        }
                    }
                    return;
                }

                let length = progress_bar.length().unwrap_or(total as u64);
                let capped_position = (completed as u64).min(length);
                let target_position = if completed >= total {
                    length
                } else {
                    capped_position
                };

                let now = Instant::now();
                if let Ok(mut last) = last_draw_time.lock() {
                    if completed >= total
                        || last
                            .map(|instant| now.duration_since(instant) >= update_interval)
                            .unwrap_or(true)
                    {
                        progress_bar.set_position(target_position);
                        *last = Some(now);
                    }
                }
            }
        }));
    }
    debug!("Scanner finished building: {scanner:?}");

    let portscan_start = Instant::now();
    let mut portscan_bench = NamedTimer::start("端口扫描");
    let scan_result = block_on(scanner.run());

    if let Some(progress_bar) = portscan_progress_bar {
        progress_bar.finish_and_clear();
        portscan_progress_guard.take();
    }
    portscan_bench.end();
    benchmarks.push(portscan_bench);

    let scan_duration_secs = portscan_start.elapsed().as_secs_f64();

    let mut ports_per_ip: HashMap<IpAddr, Vec<u16>> = HashMap::new();

    for socket in scan_result {
        ports_per_ip
            .entry(socket.ip())
            .or_insert_with(Vec::new)
            .push(socket.port());
    }

    for ports in ports_per_ip.values_mut() {
        ports.sort_unstable();
    }

    if opts.greppable {
        progress_println(format!("扫描耗时：{scan_duration_secs:.2}秒"));
    } else {
        if !opts.accessible && !ports_per_ip.is_empty() {
            progress_println(String::new());
        }
        let prefix = if opts.accessible { "" } else { " " };
        let duration_message = format!("{prefix}扫描耗时：{scan_duration_secs:.2}秒");
        detail!(duration_message, opts.greppable, opts.accessible);
    }

    let mut reporting_bench = NamedTimer::start("结果汇总");
    probe_web_services(&ports_per_ip, &opts);

    let mut all_ports: Vec<u16> = ports_per_ip
        .values()
        .flat_map(|ports| ports.iter().copied())
        .collect();
    all_ports.sort_unstable();
    all_ports.dedup();

    if !ports_per_ip.is_empty() {
        if !opts.greppable && !opts.accessible {
            progress_println(String::new());
        }

        let mut ordered_ips: Vec<IpAddr> = ports_per_ip.keys().copied().collect();
        ordered_ips.sort();

        for ip in ordered_ips {
            if let Some(ports) = ports_per_ip.get(&ip) {
                let vec_str_ports: Vec<String> = ports.iter().map(ToString::to_string).collect();

                // Ports are printed as 80,443 (comma separated without spaces).
                let ports_str = vec_str_ports.join(",");
                let open_count = ports.len();

                if opts.greppable {
                    progress_println(format!("{ip} 总端口数（{open_count}）: [{ports_str}]"));
                    continue;
                }

                let prefix = if opts.accessible { "" } else { " " };
                let heading = format!("{prefix}{ip} 总端口数（{open_count}）: [{ports_str}]");
                detail!(heading, opts.greppable, opts.accessible);
            }
        }

        let all_ports_str = all_ports
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let total_open_ports = all_ports.len();

        if opts.greppable {
            progress_println(format!(
                "总计开放端口数（{total_open_ports}）：[{all_ports_str}]"
            ));
        } else {
            let prefix = if opts.accessible { "" } else { " " };
            let summary =
                format!("{prefix}总计开放端口数（{total_open_ports}）：[{all_ports_str}]");
            detail!(summary, opts.greppable, opts.accessible);
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

const MAX_TITLE_LENGTH: usize = 100;
const MAX_TITLE_DISPLAY_LENGTH: usize = 60;
const MAX_URL_DISPLAY_LENGTH: usize = 70;
const EMPTY_TITLE: &str = "\"\"";
const NO_TITLE_TEXT: &str = "无标题";
const USER_AGENT_VALUE: &str =
    "Mozilla/5.0 (compatible; RustScan/HTTP-Probe; +https://github.com/rustscan/rustscan)";
const ACCEPT_HEADER_VALUE: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const THREAD_NAME_PREFIX: &str = "http-probe";

fn create_progress_bar(total: u64, message: &str, accessible: bool, draw_hz: u8) -> ProgressBar {
    let progress_bar = ProgressBar::new(total).with_finish(ProgressFinish::AndClear);

    if Term::stderr().is_term() {
        let template = if accessible {
            "{msg} [{bar:40}] {pos:>5}/{len:<5} {percent:>3}%"
        } else {
            "{msg} {wide_bar:.cyan/blue} {pos:>5}/{len:<5} {percent:>3}%"
        };

        let style =
            ProgressStyle::with_template(template).unwrap_or_else(|_| ProgressStyle::default_bar());
        let style = if accessible {
            style.progress_chars("=>-")
        } else {
            style.progress_chars("█▓░")
        };

        progress_bar.set_style(style);
        progress_bar.set_draw_target(ProgressDrawTarget::stderr_with_hz(draw_hz));
    } else {
        progress_bar.set_draw_target(ProgressDrawTarget::hidden());
    }

    progress_bar.set_message(message.to_string());
    progress_bar
}

fn probe_web_services(ports_per_ip: &HashMap<IpAddr, Vec<u16>>, opts: &Opts) {
    if ports_per_ip.is_empty() {
        return;
    }

    let total_http_targets: usize = ports_per_ip.values().map(|ports| ports.len()).sum();

    let timeout_secs = opts.http_timeout.max(1);
    let request_timeout = Duration::from_secs(timeout_secs);
    let detection_timeout = (request_timeout / 2).max(Duration::from_millis(500));

    let default_headers = default_http_headers();

    let client_no_redirect = match build_http_client(&default_headers, false, request_timeout) {
        Ok(client) => client,
        Err(error) => {
            warning!(
                format!("构建 HTTP 探测客户端失败: {error}"),
                opts.greppable,
                opts.accessible
            );
            return;
        }
    };

    let client_follow_redirect = match build_http_client(&default_headers, true, request_timeout) {
        Ok(client) => client,
        Err(error) => {
            warning!(
                format!("构建支持重定向的 HTTP 客户端失败: {error}"),
                opts.greppable,
                opts.accessible
            );
            return;
        }
    };

    let thread_count = usize::from(opts.http_threads.max(1));
    let pool = match ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .thread_name(|idx| format!("{THREAD_NAME_PREFIX}-{idx}"))
        .build()
    {
        Ok(pool) => pool,
        Err(error) => {
            warning!(
                format!("初始化 HTTP 探测线程池失败: {error}"),
                opts.greppable,
                opts.accessible
            );
            return;
        }
    };

    let client_no_redirect = Arc::new(client_no_redirect);
    let client_follow_redirect = Arc::new(client_follow_redirect);
    let http_findings = Arc::new(Mutex::new(Vec::new()));
    let greppable = opts.greppable;
    let accessible = opts.accessible;

    let mut progress_guard: Option<ProgressBarGuard> = None;
    let progress_bar = if greppable || total_http_targets == 0 {
        None
    } else {
        let bar = create_progress_bar(
            total_http_targets as u64,
            "HTTP 探测进度",
            accessible,
            HTTP_PROGRESS_DRAW_HZ,
        );
        progress_guard = Some(register_progress_bar(&bar));
        Some(bar)
    };
    let progress_bar_for_threads = progress_bar.clone();

    pool.scope(|scope| {
        for (ip, ports) in ports_per_ip {
            for &port in ports {
                let client_no_redirect = Arc::clone(&client_no_redirect);
                let client_follow_redirect = Arc::clone(&client_follow_redirect);
                let findings = Arc::clone(&http_findings);
                let greppable = greppable;
                let accessible = accessible;
                let ip = *ip;
                let progress_bar = progress_bar_for_threads.clone();
                scope.spawn(move |_| {
                    if let Some(finding) = probe_single_port(
                        ip,
                        port,
                        detection_timeout,
                        &client_no_redirect,
                        &client_follow_redirect,
                    ) {
                        let status_message = format_http_finding_status(&finding);

                        if let Some(pb) = &progress_bar {
                            pb.set_message(format!("HTTP 探测进度 | {status_message}"));
                        } else {
                            emit_http_finding_line(&status_message, greppable, accessible);
                        }

                        if let Ok(mut urls) = findings.lock() {
                            urls.push(finding);
                        }
                    }

                    if let Some(pb) = progress_bar {
                        pb.inc(1);
                    }
                });
            }
        }
    });

    if let Some(pb) = &progress_bar {
        pb.finish_and_clear();
        progress_guard.take();
    }

    let findings = match Arc::try_unwrap(http_findings) {
        Ok(mutex) => match mutex.into_inner() {
            Ok(vec) => vec,
            Err(poisoned) => poisoned.into_inner(),
        },
        Err(arc) => match arc.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        },
    };

    if findings.is_empty() {
        return;
    }

    let mut findings = findings;
    findings.sort_by(|a, b| a.url.cmp(&b.url));
    findings.dedup_by(|a, b| a.url == b.url);

    print_http_findings(&findings, opts.accessible);

    let urls: BTreeSet<String> = findings.iter().map(|finding| finding.url.clone()).collect();

    if let Err(error) = write_urls_file(&urls) {
        warning!(
            format!("写入 urls.txt 失败: {error}"),
            opts.greppable,
            opts.accessible
        );
    }
}

fn probe_single_port(
    ip: IpAddr,
    port: u16,
    detection_timeout: Duration,
    client_no_redirect: &Client,
    client_follow_redirect: &Client,
) -> Option<HttpProbeFinding> {
    let mut url = initialize_url(ip, port, detection_timeout);

    let mut response = match fetch_url(client_no_redirect, &url) {
        Ok(resp) => resp,
        Err(error) => {
            debug!("请求 {url} 失败: {error}");

            if url.starts_with("https://") {
                let fallback = url.replacen("https://", "http://", 1);
                match fetch_url(client_no_redirect, &fallback) {
                    Ok(resp) => {
                        url = fallback;
                        resp
                    }
                    Err(fallback_error) => {
                        debug!("降级到 HTTP 后请求 {fallback} 仍然失败: {fallback_error}");
                        return None;
                    }
                }
            } else if url.starts_with("http://") {
                let upgrade = url.replacen("http://", "https://", 1);
                match fetch_url(client_no_redirect, &upgrade) {
                    Ok(resp) => {
                        url = upgrade;
                        resp
                    }
                    Err(upgrade_error) => {
                        debug!("升级到 HTTPS 后请求 {upgrade} 失败: {upgrade_error}");
                        return None;
                    }
                }
            } else {
                return None;
            }
        }
    };

    if response.status_code == 400 && !url.starts_with("https://") {
        let upgrade = url.replacen("http://", "https://", 1);
        if let Ok(upgraded_response) = fetch_url(client_no_redirect, &upgrade) {
            url = upgrade;
            response = upgraded_response;
        }
    }

    if let Some(redirect_url) = response.redirect_url() {
        match fetch_url(client_follow_redirect, &redirect_url) {
            Ok(redirect_response) => {
                url = redirect_response.url.clone();
                response = redirect_response;
            }
            Err(error) => {
                debug!("跟随重定向 {redirect_url} 失败: {error}");
            }
        }
    }

    let status_code = response.status_code;
    let length_str = response.content_length_string();
    let body = response.into_body();
    let preview_len = body.len().min(512_000);
    let body_text = decode_body(&body[..preview_len]);
    let title = extract_title_from_body(&body_text);

    let length_display = human_readable_size(&length_str);

    Some(HttpProbeFinding {
        url,
        status_code,
        length_display,
        title,
    })
}

fn emit_http_finding_line(message: &str, greppable: bool, accessible: bool) {
    if greppable || accessible {
        progress_println(message.to_string());
    } else {
        progress_println(message.cyan().to_string());
    }
}

fn format_http_finding_status(finding: &HttpProbeFinding) -> String {
    let title_display = if finding.title.is_empty() {
        NO_TITLE_TEXT
    } else {
        &finding.title
    };

    format!(
        "实时发现 HTTP 服务 -> URL: {} | 状态: {} | 大小: {} | 标题: {}",
        finding.url, finding.status_code, finding.length_display, title_display
    )
}

fn default_http_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static(USER_AGENT_VALUE));
    headers.insert(ACCEPT, HeaderValue::from_static(ACCEPT_HEADER_VALUE));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("zh-CN,zh;q=0.9"));
    headers.insert(CONNECTION, HeaderValue::from_static("close"));
    headers
}

fn build_http_client(
    headers: &HeaderMap,
    follow_redirects: bool,
    request_timeout: Duration,
) -> Result<Client, reqwest::Error> {
    let mut builder = Client::builder()
        .timeout(request_timeout)
        .connect_timeout(request_timeout)
        .default_headers(headers.clone())
        .danger_accept_invalid_certs(true);

    builder = if follow_redirects {
        builder.redirect(Policy::limited(10))
    } else {
        builder.redirect(Policy::none())
    };

    builder.build()
}

#[derive(Clone, Copy)]
enum Protocol {
    Http,
    Https,
}

fn initialize_url(ip: IpAddr, port: u16, timeout: Duration) -> String {
    match port {
        80 => format!("http://{ip}"),
        443 => format!("https://{ip}"),
        _ => {
            let protocol = detect_protocol(ip, port, timeout);
            match protocol {
                Protocol::Https => format!("https://{ip}:{port}"),
                Protocol::Http => format!("http://{ip}:{port}"),
            }
        }
    }
}

fn detect_protocol(ip: IpAddr, port: u16, timeout: Duration) -> Protocol {
    if check_https(ip, port, timeout) {
        Protocol::Https
    } else if check_http(ip, port, timeout) {
        Protocol::Http
    } else {
        Protocol::Http
    }
}

fn check_https(ip: IpAddr, port: u16, timeout: Duration) -> bool {
    let connector = match TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(connector) => connector,
        Err(error) => {
            debug!("构建 TLS 连接器失败: {error}");
            return false;
        }
    };

    let addr = SocketAddr::new(ip, port);
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(stream) => {
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            connector.connect(&ip.to_string(), stream).is_ok()
        }
        Err(error) => {
            debug!("与 {addr} 建立 TCP 连接失败（HTTPS 探测）: {error}");
            false
        }
    }
}

fn check_http(ip: IpAddr, port: u16, timeout: Duration) -> bool {
    let addr = SocketAddr::new(ip, port);
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(mut stream) => {
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            let request = format!(
                "HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: RustScan-HTTP-Probe\r\nConnection: close\r\n\r\n"
            );
            if stream.write_all(request.as_bytes()).is_ok() {
                let mut buffer = [0_u8; 1024];
                if let Ok(read) = stream.read(&mut buffer) {
                    if read > 0 {
                        let response = String::from_utf8_lossy(&buffer[..read]);
                        return response.contains("HTTP/");
                    }
                }
            }
            false
        }
        Err(error) => {
            debug!("与 {addr} 建立 TCP 连接失败（HTTP 探测）: {error}");
            false
        }
    }
}

#[derive(Clone)]
struct HttpProbeFinding {
    url: String,
    status_code: u16,
    length_display: String,
    title: String,
}

struct WebResponse {
    url: String,
    status_code: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl WebResponse {
    fn redirect_url(&self) -> Option<String> {
        if !(300..=399).contains(&self.status_code) {
            return None;
        }

        let location = self.headers.get(LOCATION)?;
        let location_str = location.to_str().ok()?;
        if location_str.is_empty() {
            return None;
        }

        let base = Url::parse(&self.url).ok()?;
        base.join(location_str).ok().map(|url| url.to_string())
    }

    fn content_length_string(&self) -> String {
        self.headers
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .map_or_else(|| self.body.len().to_string(), |value| value.to_string())
    }

    fn into_body(self) -> Vec<u8> {
        self.body
    }
}

fn fetch_url(client: &Client, url: &str) -> Result<WebResponse, reqwest::Error> {
    let response = client.get(url).send()?;
    let status_code = response.status().as_u16();
    let headers = response.headers().clone();
    let final_url = response.url().to_string();
    let body = response.bytes()?.to_vec();

    Ok(WebResponse {
        url: final_url,
        status_code,
        headers,
        body,
    })
}

fn decode_body(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(valid) => valid.to_string(),
        Err(_) => {
            let (decoded, _, _) = GB18030.decode(bytes);
            decoded.into_owned()
        }
    }
}

fn extract_title_from_body(body: &str) -> String {
    static TITLE_REGEX: OnceCell<Regex> = OnceCell::new();
    let regex = TITLE_REGEX
        .get_or_init(|| Regex::new("(?is)<title.*?>(.*?)</title>").expect("有效的标题匹配表达式"));

    if let Some(caps) = regex.captures(body) {
        if let Some(matched) = caps.get(1) {
            let cleaned = matched
                .as_str()
                .replace(['\n', '\r'], " ")
                .replace("&nbsp;", " ");
            let collapsed = cleaned
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .trim()
                .to_string();

            if collapsed.is_empty() {
                return EMPTY_TITLE.to_string();
            }

            let truncated: String = collapsed.chars().take(MAX_TITLE_LENGTH).collect();
            return truncated;
        }
    }

    NO_TITLE_TEXT.to_string()
}

fn print_http_findings(findings: &[HttpProbeFinding], accessible: bool) {
    if findings.is_empty() {
        return;
    }

    let mut ordered_findings: Vec<&HttpProbeFinding> = findings.iter().collect();
    ordered_findings.sort_by(|a, b| a.url.cmp(&b.url));

    let display_items: Vec<(String, String, &HttpProbeFinding)> = ordered_findings
        .into_iter()
        .map(|finding| {
            let url_display = truncate_with_ellipsis(&finding.url, MAX_URL_DISPLAY_LENGTH);
            let title_display = truncate_with_ellipsis(&finding.title, MAX_TITLE_DISPLAY_LENGTH);
            (url_display, title_display, finding)
        })
        .collect();

    let url_width = display_items
        .iter()
        .map(|(url_display, _, _)| url_display.len())
        .max()
        .unwrap_or(3)
        .max("URL".len());

    let length_width = findings
        .iter()
        .map(|finding| finding.length_display.len())
        .max()
        .unwrap_or(1)
        .max("大小".len());

    let title_width = display_items
        .iter()
        .map(|(_, title_display, _)| title_display.len())
        .max()
        .unwrap_or("标题".len());

    let status_width = 5usize;

    let separator_char = if accessible { '-' } else { '─' };
    let url_rule: String = std::iter::repeat(separator_char).take(url_width).collect();
    let status_rule: String = std::iter::repeat(separator_char)
        .take(status_width)
        .collect();
    let length_rule: String = std::iter::repeat(separator_char)
        .take(length_width)
        .collect();
    let title_rule: String = std::iter::repeat(separator_char)
        .take(title_width)
        .collect();

    let header_row = format!(
        "{:<url_width$}  {:>status_width$}  {:>length_width$}  {:<title_width$}",
        "URL",
        "状态",
        "大小",
        "标题",
        url_width = url_width,
        status_width = status_width,
        length_width = length_width,
        title_width = title_width
    );

    let separator_row = format!(
        "{url_rule}  {status_rule}  {length_rule}  {title_rule}",
        url_rule = url_rule,
        status_rule = status_rule,
        length_rule = length_rule,
        title_rule = title_rule
    );

    progress_println(String::new());

    if accessible {
        progress_println(format!("HTTP 服务探测结果（共 {} 个）", findings.len()));
        progress_println(header_row.clone());
        progress_println(separator_row.clone());
    } else {
        let heading = format!("HTTP 服务探测结果（共 {} 个）", findings.len());
        progress_println(heading.cyan().bold().to_string());
        progress_println(header_row.white().bold().to_string());
        progress_println(separator_row.clone());
    }

    for (url_display, title_display, finding) in display_items {
        let url_column = format!("{:<url_width$}", url_display, url_width = url_width);
        let url_column = if accessible {
            url_column
        } else {
            format!("{}", url_column.cyan())
        };

        let status_column = format!(
            "{:>status_width$}",
            finding.status_code,
            status_width = status_width
        );
        let status_column = stylize_status(status_column, finding.status_code, accessible);

        let length_column = format!(
            "{:>length_width$}",
            finding.length_display,
            length_width = length_width
        );
        let length_column = if accessible {
            length_column
        } else {
            format!("{}", length_column.yellow())
        };

        let title_column = format!("{:<title_width$}", title_display, title_width = title_width);
        let title_column = if accessible {
            title_column
        } else {
            format!("{}", title_column.white())
        };

        progress_println(format!(
            "{url_column}  {status_column}  {length_column}  {title_column}"
        ));
    }
}

fn stylize_status(status: String, code: u16, accessible: bool) -> String {
    if accessible {
        return status;
    }

    if (200..=299).contains(&code) {
        format!("{}", status.green().bold())
    } else if (300..=399).contains(&code) {
        format!("{}", status.yellow().bold())
    } else if (400..=599).contains(&code) {
        format!("{}", status.red().bold())
    } else {
        format!("{}", status.white())
    }
}

fn truncate_with_ellipsis(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }

    if max_chars <= 1 {
        return "…".to_string();
    }

    let mut truncated = text.chars().take(max_chars - 1).collect::<String>();
    truncated.push('…');
    truncated
}

fn human_readable_size(length: &str) -> String {
    if let Ok(value) = length.parse::<u64>() {
        return format_bytes(value);
    }

    length.to_string()
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit_index = 0;

    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{value:.2} {}", UNITS[unit_index])
    }
}

fn write_urls_file(urls: &BTreeSet<String>) -> std::io::Result<()> {
    let file = File::create("urls.txt")?;
    let mut writer = BufWriter::new(file);

    for url in urls {
        writeln!(writer, "{url}")?;
    }

    writer.flush()
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

    progress_println(s.gradient(Color::Green).bold().to_string());
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
