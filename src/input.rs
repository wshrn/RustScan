//! 提供扫描参数的解析与存储功能。
use clap::{Parser, ValueEnum};

const LOWEST_PORT_NUMBER: u16 = 1;
const TOP_PORT_NUMBER: u16 = 65535;

/// Represents the strategy in which the port scanning will run.
///   - Serial will run from start to end, for example 1 to 1_000.
///   - Random will randomize the order in which ports will be scanned.
#[derive(Debug, ValueEnum, Clone, Copy, PartialEq, Eq)]
pub enum ScanOrder {
    Serial,
    Random,
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
        .map(str::parse)
        .collect::<Result<Vec<u16>, std::num::ParseIntError>>();

    if range.is_err() {
        return Err(String::from(
            "端口范围格式必须为 '起始-结束'，例如：1-1000。",
        ));
    }

    match range.unwrap().as_slice() {
        [start, end] => Ok(PortRange {
            start: *start,
            end: *end,
        }),
        _ => Err(String::from(
            "端口范围格式必须为 '起始-结束'，例如：1-1000。",
        )),
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "rustscan",
    version = env!("CARGO_PKG_VERSION"),
    max_term_width = 120,
    help_template = "{bin} {version}\n{about}\n\n用法:\n    {usage}\n\n选项:\n{options}",
)]
#[allow(clippy::struct_excessive_bools)]
/// 高速端口扫描器，采用 Rust 构建。
/// 警告：请勿对敏感基础设施使用本程序，目标服务器可能无法承受大量并发套接字。
pub struct Opts {
    /// 待扫描的 CIDR、IP 或主机，使用英文逗号分隔，或提供逐行的文件路径。
    #[arg(short, long, value_delimiter = ',')]
    pub addresses: Vec<String>,

    /// 以英文逗号分隔的端口列表，例如：80,443,8080。
    #[arg(short, long, value_delimiter = ',')]
    pub ports: Option<Vec<u16>>,

    /// 端口范围，格式为 起始-结束，例如：1-1000。
    #[arg(short, long, conflicts_with = "ports", value_parser = parse_range)]
    pub range: Option<PortRange>,

    /// 隐藏启动横幅。
    #[arg(long)]
    pub no_banner: bool,

    /// Grep 模式：仅输出端口，方便重定向或 grep 处理。
    #[arg(short, long)]
    pub greppable: bool,

    /// 无障碍模式：关闭对屏幕阅读器不友好的效果。
    #[arg(long)]
    pub accessible: bool,

    /// DNS 解析器，支持逗号分隔列表或文件路径。
    #[arg(long)]
    pub resolver: Option<String>,

    /// 端口扫描批量大小，决定一次同时扫描的端口数量，受系统文件句柄上限影响。
    /// 若设置为 65535 将同时扫描所有端口，但操作系统可能无法支持。
    #[arg(short, long, default_value = "4500")]
    pub batch_size: u16,

    /// 端口判定为关闭前的超时时长（毫秒）。
    #[arg(short, long, default_value = "1500")]
    pub timeout: u32,

    /// 端口被视为关闭前的重试次数，若设为 0 将自动调整为 1。
    #[arg(long, default_value = "1")]
    pub tries: u8,

    /// 将系统 ulimit 调整为提供的数值。
    #[arg(short, long)]
    pub ulimit: Option<u64>,

    /// 扫描顺序：serial 顺序扫描，random 随机扫描。
    #[arg(long, value_enum, ignore_case = true, default_value = "serial")]
    pub scan_order: ScanOrder,

    /// 需要排除的端口列表（英文逗号分隔），例如：80,443,8080。
    #[arg(short, long, value_delimiter = ',')]
    pub exclude_ports: Option<Vec<u16>>,

    /// 需要排除的 CIDR、IP 或主机列表（英文逗号分隔）。
    #[arg(short = 'x', long = "exclude-addresses", value_delimiter = ',')]
    pub exclude_addresses: Option<Vec<String>>,

    /// 启用 UDP 扫描模式，发现会响应的 UDP 端口。
    #[arg(long)]
    pub udp: bool,
}

#[cfg(not(tarpaulin_include))]
impl Opts {
    pub fn read() -> Self {
        Self::read_from(std::env::args_os())
    }

    pub fn read_from<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        let mut opts = Opts::parse_from(args);

        if opts.ports.is_none() && opts.range.is_none() {
            opts.range = Some(PortRange {
                start: LOWEST_PORT_NUMBER,
                end: TOP_PORT_NUMBER,
            });
        }

        opts
    }
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            addresses: vec![],
            ports: None,
            range: None,
            greppable: true,
            batch_size: 0,
            timeout: 0,
            tries: 0,
            ulimit: None,
            accessible: false,
            resolver: None,
            scan_order: ScanOrder::Serial,
            no_banner: false,
            exclude_ports: None,
            exclude_addresses: None,
            udp: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Opts;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Opts::command().debug_assert();
    }

    #[test]
    fn opts_default_range_falls_back_to_full_scan() {
        let opts = Opts::default();
        assert_eq!(opts.range, None);
        assert!(opts.ports.is_none());

        let parsed_opts = Opts::read_from(["rustscan"]);
        let range = parsed_opts.range.expect("默认解析应生成完整的端口范围");

        assert_eq!(range.start, super::LOWEST_PORT_NUMBER);
        assert_eq!(range.end, super::TOP_PORT_NUMBER);
    }
}
