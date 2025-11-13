//! 提供扫描参数的解析与存储功能。
use clap::{Parser, ValueEnum};
use std::collections::HashSet;
use std::ffi::OsString;
use std::str::FromStr;

const LOWEST_PORT_NUMBER: u16 = 1;
const TOP_PORT_NUMBER: u16 = 65535;

/// Represents the strategy in which the port scanning will run.
///   - Serial will run from start to end, for example 1 to 1_000.
///   - Random will randomize the order in which ports will be scanned.
#[derive(Debug, ValueEnum, Clone, Copy, PartialEq, Eq)]
#[value(rename_all = "kebab-case")]
pub enum ScanOrder {
    Serial,
    Random,
    HighFrequency,
}

/// Represents the range of ports to be scanned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[cfg(not(tarpaulin_include))]
fn parse_range(input: &str) -> Result<PortRange, String> {
    let range = input
        .split('-')
        .map(|segment| segment.trim().parse::<u16>())
        .collect::<Result<Vec<u16>, std::num::ParseIntError>>();

    if range.is_err() {
        return Err(String::from(
            "端口范围格式必须为 '起始-结束'，例如：1-1000。",
        ));
    }

    match range.unwrap().as_slice() {
        [start, end] if start <= end => Ok(PortRange {
            start: *start,
            end: *end,
        }),
        _ => Err(String::from(
            "端口范围格式必须为 '起始-结束'，例如：1-1000。",
        )),
    }
}

/// Represents the user's port selection, either a range or a concrete list of ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortSelection {
    Range(PortRange),
    List(Vec<u16>),
}

impl From<PortRange> for PortSelection {
    fn from(range: PortRange) -> Self {
        Self::Range(range)
    }
}

impl From<Vec<u16>> for PortSelection {
    fn from(ports: Vec<u16>) -> Self {
        Self::List(ports)
    }
}

impl FromStr for PortSelection {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(String::from("端口参数不能为空。"));
        }

        let segments: Vec<&str> = trimmed
            .split(',')
            .map(str::trim)
            .filter(|segment| !segment.is_empty())
            .collect();

        if segments.is_empty() {
            return Err(String::from("端口参数不能为空。"));
        }

        if segments.len() == 1 && segments[0].contains('-') {
            return parse_range(segments[0]).map(PortSelection::Range);
        }

        let mut unique_ports = HashSet::new();
        let mut ports = Vec::new();

        for segment in segments {
            if segment.contains('-') {
                let range = parse_range(segment)?;
                for port in range.start..=range.end {
                    if unique_ports.insert(port) {
                        ports.push(port);
                    }
                }
            } else {
                let port: u16 = segment
                    .parse()
                    .map_err(|_| format!("无法解析端口 '{segment}'，请输入合法的端口号或范围。"))?;

                if unique_ports.insert(port) {
                    ports.push(port);
                }
            }
        }

        if ports.is_empty() {
            return Err(String::from("端口参数不能为空。"));
        }

        Ok(PortSelection::List(ports))
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "rustscan",
    version = env!("CARGO_PKG_VERSION"),
    max_term_width = 120,
    about = "高速端口扫描器，采用 Rust 构建。",
    long_about = "高速端口扫描器，采用 Rust 构建。\n警告：请勿对敏感基础设施使用本程序，目标服务器可能无法承受大量并发套接字。",
    help_template = "{name} {version}\n{about}\n\n用法:\n  {usage}\n\n参数:\n{options}\n{after-help}",
    after_help = "示例:\n  rustscan -a 192.168.0.1\n  rustscan -a 192.168.0.1,10.0.0.0/24 -p 80,443 --exclude-ports 22\n  rustscan -a targets.txt -p 1-1024 --scan-order random --timeout 3000\n  rustscan -a 192.168.0.0/24 -ht 5 -hs 40",
)]
#[allow(clippy::struct_excessive_bools)]
/// RustScan 命令行参数定义。
pub struct Opts {
    /// 待扫描的 CIDR、IP 或主机，使用英文逗号分隔，或提供逐行的文件路径。
    /// 示例：`-a 192.168.0.1,10.0.0.0/24` 或 `-a targets.txt`。
    #[arg(short, long, value_delimiter = ',')]
    pub addresses: Vec<String>,

    /// 端口范围或端口列表。
    /// 示例：`-p 80,443,8080`、`-p 1-1000` 或 `-p 80,443,1000-2000`。
    #[arg(short, long, default_value = "1-65535")]
    pub ports: PortSelection,

    /// 隐藏启动横幅。
    /// 示例：`--no-banner`。
    #[arg(long)]
    pub no_banner: bool,

    /// Grep 模式：仅输出端口，方便重定向或 grep 处理。
    /// 示例：`-g` 或 `--greppable`。
    #[arg(short, long)]
    pub greppable: bool,

    /// 无障碍模式：关闭对屏幕阅读器不友好的效果。
    /// 示例：`--accessible`。
    #[arg(long)]
    pub accessible: bool,

    /// DNS 解析器，支持逗号分隔列表或文件路径。
    /// 示例：`--resolver 1.1.1.1,8.8.8.8` 或 `--resolver resolvers.txt`。
    #[arg(long)]
    pub resolver: Option<String>,

    /// 端口扫描批量大小，决定一次同时扫描的端口数量，受系统文件句柄上限影响。
    /// 若设置为 65535 将同时扫描所有端口，但操作系统可能无法支持。
    /// 示例：`-b 3500`。
    #[arg(short, long, default_value = "1200")]
    pub batch_size: u16,

    /// 端口判定为关闭前的超时时长（毫秒）。
    /// 示例：`-t 2000`。
    #[arg(short, long, default_value = "1500")]
    pub timeout: u32,

    /// 端口被视为关闭前的重试次数，若设为 0 将自动调整为 1。
    /// 示例：`--tries 3`。
    #[arg(long, default_value = "1")]
    pub tries: u8,

    /// 将系统 ulimit 调整为提供的数值。
    /// 示例：`-u 8192`。
    #[arg(short, long)]
    pub ulimit: Option<u64>,

    /// 扫描顺序：serial 顺序扫描，random 随机扫描，high-frequency 高频优先扫描。
    /// 示例：`--scan-order random`。
    #[arg(long, value_enum, ignore_case = true, default_value = "high-frequency")]
    pub scan_order: ScanOrder,

    /// 需要排除的端口列表（英文逗号分隔）。
    /// 示例：`-e 22,3389`。
    #[arg(short, long, value_delimiter = ',')]
    pub exclude_ports: Option<Vec<u16>>,

    /// 需要排除的 CIDR、IP 或主机列表（英文逗号分隔）。
    /// 示例：`-x 192.168.1.0/24,example.com`。
    #[arg(short = 'x', long = "exclude-addresses", value_delimiter = ',')]
    pub exclude_addresses: Option<Vec<String>>,

    /// 启用 UDP 扫描模式，发现会响应的 UDP 端口。
    /// 示例：`--udp`。
    #[arg(long)]
    pub udp: bool,

    /// HTTP/HTTPS 探测的超时时间（秒）。
    /// 示例：`-ht 5` 或 `--http-timeout 5`。
    #[arg(
        short = 'T',
        long = "http-timeout",
        visible_alias = "ht",
        value_name = "SECONDS",
        default_value = "3",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub http_timeout: u64,

    /// HTTP/HTTPS 探测线程池大小。
    /// 示例：`-hs 50` 或 `--http-threads 50`。
    #[arg(
        short = 'S',
        long = "http-threads",
        visible_alias = "hs",
        value_name = "THREADS",
        default_value = "20",
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    pub http_threads: u16,
}

#[cfg(not(tarpaulin_include))]
impl Opts {
    pub fn read() -> Self {
        Self::read_from(std::env::args_os())
    }

    pub fn read_from<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString>,
    {
        Opts::parse_from(normalize_args(args))
    }
}

fn normalize_args<I, T>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    args.into_iter()
        .map(Into::into)
        .map(|arg| normalize_flag(arg, "-ht", "--http-timeout"))
        .map(|arg| normalize_flag(arg, "-hs", "--http-threads"))
        .collect()
}

fn normalize_flag(arg: OsString, short_alias: &str, long_flag: &str) -> OsString {
    if let Some(value) = arg.clone().into_string().ok().and_then(|text| {
        if text == short_alias {
            Some(long_flag.to_string())
        } else if let Some(rest) = text.strip_prefix(&(short_alias.to_string() + "=")) {
            Some(format!("{long_flag}={rest}"))
        } else {
            None
        }
    }) {
        return OsString::from(value);
    }

    arg
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            addresses: vec![],
            ports: PortSelection::Range(PortRange {
                start: LOWEST_PORT_NUMBER,
                end: TOP_PORT_NUMBER,
            }),
            greppable: true,
            batch_size: 0,
            timeout: 0,
            tries: 0,
            ulimit: None,
            accessible: false,
            resolver: None,
            scan_order: ScanOrder::HighFrequency,
            no_banner: false,
            exclude_ports: None,
            exclude_addresses: None,
            udp: false,
            http_timeout: 3,
            http_threads: 20,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Opts, PortRange, PortSelection};
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Opts::command().debug_assert();
    }

    #[test]
    fn opts_default_range_falls_back_to_full_scan() {
        let opts = Opts::default();
        assert_eq!(
            opts.ports,
            PortSelection::Range(PortRange {
                start: super::LOWEST_PORT_NUMBER,
                end: super::TOP_PORT_NUMBER,
            })
        );

        let parsed_opts = Opts::read_from(["rustscan"]);
        match parsed_opts.ports {
            PortSelection::Range(range) => {
                assert_eq!(range.start, super::LOWEST_PORT_NUMBER);
                assert_eq!(range.end, super::TOP_PORT_NUMBER);
            }
            PortSelection::List(_) => panic!("默认解析应生成完整的端口范围"),
        }
    }
}
