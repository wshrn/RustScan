#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown, clippy::if_not_else, clippy::non_ascii_literal)]

use rustscan::benchmark::{Benchmark, NamedTimer};
use rustscan::input::Opts;
use rustscan::port_strategy::PortStrategy;
use rustscan::scanner::Scanner;
use rustscan::{detail, warning};

use colorful::{Color, Colorful};
use encoding_rs::GB18030;
use futures::executor::block_on;
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

    let exclude_ports = opts.exclude_ports.clone().unwrap_or_default();

    let scanner = Scanner::new(
        &ips,
        batch_size,
        Duration::from_millis(opts.timeout.into()),
        opts.tries,
        opts.greppable,
        PortStrategy::pick(&opts.ports, opts.scan_order),
        opts.accessible,
        exclude_ports,
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
    probe_web_services(&ports_per_ip, &opts);

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

const MAX_TITLE_LENGTH: usize = 100;
const MAX_TITLE_DISPLAY_LENGTH: usize = 60;
const MAX_URL_DISPLAY_LENGTH: usize = 70;
const EMPTY_TITLE: &str = "\"\"";
const NO_TITLE_TEXT: &str = "无标题";
const USER_AGENT_VALUE: &str =
    "Mozilla/5.0 (compatible; RustScan/HTTP-Probe; +https://github.com/rustscan/rustscan)";
const ACCEPT_HEADER_VALUE: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const THREAD_NAME_PREFIX: &str = "http-probe";

fn probe_web_services(ports_per_ip: &HashMap<IpAddr, Vec<u16>>, opts: &Opts) {
    if ports_per_ip.is_empty() {
        return;
    }

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

    pool.scope(|scope| {
        for (ip, ports) in ports_per_ip {
            for &port in ports {
                let client_no_redirect = Arc::clone(&client_no_redirect);
                let client_follow_redirect = Arc::clone(&client_follow_redirect);
                let findings = Arc::clone(&http_findings);
                let ip = *ip;
                scope.spawn(move |_| {
                    if let Some(finding) = probe_single_port(
                        ip,
                        port,
                        detection_timeout,
                        &client_no_redirect,
                        &client_follow_redirect,
                    ) {
                        if let Ok(mut urls) = findings.lock() {
                            urls.push(finding);
                        }
                    }
                });
            }
        }
    });

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

    let display_items: Vec<(String, String, &HttpProbeFinding)> = findings
        .iter()
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

    if accessible {
        println!();
        println!("HTTP 服务探测结果（共 {} 个）", findings.len());
        println!(
            "{:<url_width$}  {:>5}  {:>length_width$}  {:<title_width$}",
            "URL",
            "状态",
            "大小",
            "标题",
            url_width = url_width,
            length_width = length_width,
            title_width = title_width
        );
        println!(
            "{:-<url_width$}  {:-<5}  {:-<length_width$}  {:-<title_width$}",
            "",
            "",
            "",
            "",
            url_width = url_width,
            length_width = length_width,
            title_width = title_width
        );
    } else {
        println!();
        println!(
            "{}",
            format!("HTTP 服务探测结果（共 {} 个）", findings.len()).bold()
        );
        println!(
            "{:<url_width$}  {:>5}  {:>length_width$}  {:<title_width$}",
            "URL",
            "状态",
            "大小",
            "标题",
            url_width = url_width,
            length_width = length_width,
            title_width = title_width
        );
        println!(
            "{:-<url_width$}  {:-<5}  {:-<length_width$}  {:-<title_width$}",
            "",
            "",
            "",
            "",
            url_width = url_width,
            length_width = length_width,
            title_width = title_width
        );
    }

    for (url_display, title_display, finding) in display_items {
        let url_column = format!("{:<url_width$}", url_display, url_width = url_width);
        let url_column = if accessible {
            url_column
        } else {
            format!("{}", url_column.cyan())
        };

        let status_column = format!("{:>5}", finding.status_code);
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

        println!("{url_column}  {status_column}  {length_column}  {title_column}");
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

    println!("{}", s.gradient(Color::Green).bold());
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
