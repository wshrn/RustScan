//! Utilities for terminal output during scanning.

/// Terminal User Interface Module for RustScan
/// Defines macros to use
#[macro_export]
macro_rules! warning {
    ($name:expr) => {
        println!("{} {}", ansi_term::Colour::Red.bold().paint("[!]"), $name);
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        // if not greppable then print, otherwise no else statement so do not print.
        if !$greppable {
            if $accessible {
                // Don't print the ascii art
                println!("{}", $name);
            } else {
                println!("{} {}", ansi_term::Colour::Red.bold().paint("[!]"), $name);
            }
        }
    };
}

#[macro_export]
macro_rules! detail {
    ($name:expr) => {
        println!("{} {}", ansi_term::Colour::Blue.bold().paint("[~]"), $name);
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        // if not greppable then print, otherwise no else statement so do not print.
        if !$greppable {
            if $accessible {
                // Don't print the ascii art
                println!("{}", $name);
            } else {
                println!("{} {}", ansi_term::Colour::Blue.bold().paint("[~]"), $name);
            }
        }
    };
}

#[macro_export]
macro_rules! output {
    ($name:expr) => {
        println!(
            "{} {}",
            ansi_term::Colour::RGB(0, 255, 9).bold().paint("[>]"),
            $name
        );
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        // if not greppable then print, otherwise no else statement so do not print.
        if !$greppable {
            if $accessible {
                // Don't print the ascii art
                println!("{}", $name);
            } else {
                println!(
                    "{} {}",
                    ansi_term::Colour::RGB(0, 255, 9).bold().paint("[>]"),
                    $name
                );
            }
        }
    };
}

#[macro_export]
macro_rules! funny_opening {
    // prints a funny quote / opening
    () => {
        use rand::seq::IndexedRandom;
        let quotes = vec![
            "Nmap？不如叫慢扫。🐢",
            "🌍入侵地球！🌍",
            "真正的黑客连时间都能入侵 ⌛",
            "欢迎向我们的 GitHub 贡献更多金句：https://github.com/rustscan/rustscan",
            "😵 https://admin.tryhackme.com",
            "0day 到此一游 ♥",
            "我不是每次都扫端口，但出手必用 RustScan。",
            "RustScan：扫端口也要很酷。😎",
            "扫还是不扫？这是个问题。",
            "RustScan：猜测不算黑客，扫描才算。",
            "扫端口好比本职工作。等等，这本来就是。",
            "端口是开的，心门可别关上。",
            "电脑被我扫怕了，现在以为我们在约会。",
            "端口扫描，让网络世界瞬间精彩。",
            "不去扫描，就错过 100% 的端口。——RustScan",
            "破门而入……是走进开放端口的世界。",
            "TCP 握手？更像击个掌！",
            "扫描端口：虚拟世界里的挨家挨户敲门。",
            "RustScan：让“关闭”不只是心理安慰。",
            "RustScan：比 Nmap 快上 1200 倍地向虚空发送 UDP 数据包。",
            "端口扫描：每个端口都有故事。",
            "我扫端口的速度快到连电脑都惊呆了。",
            "扫描速度快到“同步确认”都来不及说完。",
            "RustScan：'404 Not Found' 与 '200 OK' 的交汇点。",
            "RustScan：一次一个 IP 地探索数字世界。",
            "TreadStone 到此打卡 🚀",
            "有了 RustScan，我扫端口快到防火墙都闪了腰。💨",
            "扫描速度太快，连互联网都收到了超速罚单！",
        ];
        let random_quote = quotes.choose(&mut rand::rng()).unwrap();

        println!("{}\n", random_quote);
    };
}
