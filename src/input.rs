//! Provides a means to read, parse and hold configuration options for scans.
use clap::{Parser, ValueEnum};
use serde_derive::Deserialize;
use std::fs;
use std::path::PathBuf;

const LOWEST_PORT_NUMBER: u16 = 1;
const TOP_PORT_NUMBER: u16 = 65535;

/// Represents the strategy in which the port scanning will run.
///   - Serial will run from start to end, for example 1 to 1_000.
///   - Random will randomize the order in which ports will be scanned.
#[derive(Deserialize, Debug, ValueEnum, Clone, Copy, PartialEq, Eq)]
pub enum ScanOrder {
    Serial,
    Random,
}

/// Represents the range of ports to be scanned.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
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
/// - Discord  <http://discord.skerritt.blog>
/// - GitHub <https://github.com/RustScan/RustScan>
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

    /// 是否忽略配置文件。
    #[arg(short, long)]
    pub no_config: bool,

    /// 隐藏启动横幅。
    #[arg(long)]
    pub no_banner: bool,

    /// 指定配置文件路径。
    #[arg(short, long, value_parser)]
    pub config_path: Option<PathBuf>,

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

    /// 是否使用预设的前 1000 个常见端口。
    #[arg(long)]
    pub top: bool,

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
        let mut opts = Opts::parse();

        if opts.ports.is_none() && opts.range.is_none() {
            opts.range = Some(PortRange {
                start: LOWEST_PORT_NUMBER,
                end: TOP_PORT_NUMBER,
            });
        }

        opts
    }

    /// 读取命令行参数并合并配置文件中的设置。
    pub fn merge(&mut self, config: &Config) {
        if !self.no_config {
            self.merge_required(config);
            self.merge_optional(config);
        }
    }

    fn merge_required(&mut self, config: &Config) {
        macro_rules! merge_required {
            ($($field: ident),+) => {
                $(
                    if let Some(e) = &config.$field {
                        self.$field = e.clone();
                    }
                )+
            }
        }

        merge_required!(
            addresses, greppable, accessible, batch_size, timeout, tries, scan_order, udp
        );
    }

    fn merge_optional(&mut self, config: &Config) {
        macro_rules! merge_optional {
            ($($field: ident),+) => {
                $(
                    if config.$field.is_some() {
                        self.$field = config.$field.clone();
                    }
                )+
            }
        }

        // Only use top ports when the user asks for them
        if self.top && config.ports.is_some() {
            self.ports = config.ports.clone();
        }

        merge_optional!(range, resolver, ulimit, exclude_ports, exclude_addresses);
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
            no_config: true,
            no_banner: false,
            top: false,
            config_path: None,
            exclude_ports: None,
            exclude_addresses: None,
            udp: false,
        }
    }
}

/// Struct used to deserialize the options specified within our config file.
/// These will be further merged with our command line arguments in order to
/// generate the final Opts struct.
#[cfg(not(tarpaulin_include))]
#[derive(Debug, Deserialize)]
pub struct Config {
    addresses: Option<Vec<String>>,
    ports: Option<Vec<u16>>,
    range: Option<PortRange>,
    greppable: Option<bool>,
    accessible: Option<bool>,
    batch_size: Option<u16>,
    timeout: Option<u32>,
    tries: Option<u8>,
    ulimit: Option<u64>,
    resolver: Option<String>,
    scan_order: Option<ScanOrder>,
    exclude_ports: Option<Vec<u16>>,
    exclude_addresses: Option<Vec<String>>,
    udp: Option<bool>,
}

#[cfg(not(tarpaulin_include))]
#[allow(clippy::doc_link_with_quotes)]
#[allow(clippy::manual_unwrap_or_default)]
impl Config {
    /// Reads the configuration file with TOML format and parses it into a
    /// Config struct.
    ///
    /// # Format
    ///
    /// addresses = ["127.0.0.1", "127.0.0.1"]
    /// ports = [80, 443, 8080]
    /// greppable = true
    /// scan_order = "Serial"
    /// exclude_ports = [8080, 9090, 80]
    /// udp = false
    ///
    pub fn read(custom_config_path: Option<PathBuf>) -> Self {
        let mut content = String::new();
        let config_path = custom_config_path.unwrap_or_else(default_config_path);
        if config_path.exists() {
            content = match fs::read_to_string(config_path) {
                Ok(content) => content,
                Err(_) => String::new(),
            }
        }

        let config: Config = match toml::from_str(&content) {
            Ok(config) => config,
            Err(e) => {
                println!("在配置文件中发现错误 {e}。\n已终止扫描。\n");
                std::process::exit(1);
            }
        };

        config
    }
}

/// Constructs default path to config toml
pub fn default_config_path() -> PathBuf {
    let Some(mut config_path) = dirs::home_dir() else {
        panic!("无法确定配置文件路径。");
    };
    config_path.push(".rustscan.toml");
    config_path
}

#[cfg(test)]
mod tests {
    use super::{Config, Opts, PortRange, ScanOrder};
    use clap::CommandFactory;

    impl Config {
        fn default() -> Self {
            Self {
                addresses: Some(vec!["127.0.0.1".to_owned()]),
                ports: None,
                range: None,
                greppable: Some(true),
                batch_size: Some(25_000),
                timeout: Some(1_000),
                tries: Some(1),
                ulimit: None,
                accessible: Some(true),
                resolver: None,
                scan_order: Some(ScanOrder::Random),
                exclude_ports: None,
                exclude_addresses: None,
                udp: Some(false),
            }
        }
    }

    #[test]
    fn verify_cli() {
        Opts::command().debug_assert();
    }

    #[test]
    fn opts_no_merge_when_config_is_ignored() {
        let mut opts = Opts::default();
        let config = Config::default();

        opts.merge(&config);

        assert_eq!(opts.addresses, vec![] as Vec<String>);
        assert!(opts.greppable);
        assert!(!opts.accessible);
        assert_eq!(opts.timeout, 0);
        assert_eq!(opts.scan_order, ScanOrder::Serial);
    }

    #[test]
    fn opts_merge_required_arguments() {
        let mut opts = Opts::default();
        let config = Config::default();

        opts.merge_required(&config);

        assert_eq!(opts.addresses, config.addresses.unwrap());
        assert_eq!(opts.greppable, config.greppable.unwrap());
        assert_eq!(opts.timeout, config.timeout.unwrap());
        assert_eq!(opts.accessible, config.accessible.unwrap());
        assert_eq!(opts.scan_order, config.scan_order.unwrap());
    }

    #[test]
    fn opts_merge_optional_arguments() {
        let mut opts = Opts::default();
        let mut config = Config::default();
        config.range = Some(PortRange {
            start: 1,
            end: 1_000,
        });
        config.ulimit = Some(1_000);
        config.resolver = Some("1.1.1.1".to_owned());

        opts.merge_optional(&config);

        assert_eq!(opts.range, config.range);
        assert_eq!(opts.ulimit, config.ulimit);
        assert_eq!(opts.resolver, config.resolver);
    }
}
