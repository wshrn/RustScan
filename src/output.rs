use colorful::Colorful;
use console::Term;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressFinish, ProgressStyle};

pub const MAX_TITLE_LENGTH: usize = 100;
pub const MAX_TITLE_DISPLAY_LENGTH: usize = 60;
pub const MAX_URL_DISPLAY_LENGTH: usize = 70;
pub const EMPTY_TITLE: &str = "\"\"";
pub const NO_TITLE_TEXT: &str = "无标题";
const STATUS_COLUMN_WIDTH: usize = 5;

#[derive(Clone)]
pub struct HttpProbeFinding {
    pub url: String,
    pub status_code: u16,
    pub length_display: String,
    pub title: String,
}

struct HttpTableDimensions {
    url: usize,
    status: usize,
    length: usize,
    title: usize,
}

pub fn create_progress_bar(
    total: u64,
    message: &str,
    accessible: bool,
    draw_hz: u8,
) -> ProgressBar {
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

pub fn print_http_findings(findings: &[HttpProbeFinding], accessible: bool) {
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

    let widths = HttpTableDimensions {
        url: display_items
            .iter()
            .map(|(url_display, _, _)| url_display.len())
            .max()
            .unwrap_or(3)
            .max("URL".len()),
        status: STATUS_COLUMN_WIDTH,
        length: findings
            .iter()
            .map(|finding| finding.length_display.len())
            .max()
            .unwrap_or(1)
            .max("大小".len()),
        title: display_items
            .iter()
            .map(|(_, title_display, _)| title_display.len())
            .max()
            .unwrap_or("标题".len()),
    };

    let header_row = http_table_header_row(&widths);
    let separator_row = http_table_separator_row(&widths, accessible);

    if accessible {
        println!("{header_row}");
    } else {
        println!("{}", header_row.white().bold());
    }
    println!("{separator_row}");

    for (url_display, title_display, finding) in display_items {
        let row = format_http_table_row(&url_display, &title_display, finding, &widths, accessible);
        println!("{row}");
    }
}

pub fn build_realtime_http_output(
    finding: &HttpProbeFinding,
    include_header: bool,
    accessible: bool,
) -> (Vec<String>, String) {
    let url_display = truncate_with_ellipsis(&finding.url, MAX_URL_DISPLAY_LENGTH);
    let title_display = truncate_with_ellipsis(&finding.title, MAX_TITLE_DISPLAY_LENGTH);
    let widths = HttpTableDimensions {
        url: url_display.len().max("URL".len()),
        status: STATUS_COLUMN_WIDTH,
        length: finding.length_display.len().max("大小".len()),
        title: title_display.len().max("标题".len()),
    };

    let mut lines = Vec::new();

    if include_header {
        let header_row = http_table_header_row(&widths);
        if accessible {
            lines.push(header_row);
        } else {
            lines.push(format!("{}", header_row.white().bold()));
        }

        lines.push(http_table_separator_row(&widths, accessible));
    }

    let colored_row =
        format_http_table_row(&url_display, &title_display, finding, &widths, accessible);
    let plain_row = format_http_table_row(&url_display, &title_display, finding, &widths, true);
    lines.push(colored_row);

    (lines, plain_row)
}

pub fn format_http_finding_line(message: &str, greppable: bool, accessible: bool) -> String {
    if greppable || accessible {
        message.to_string()
    } else {
        message.cyan().to_string()
    }
}

pub fn format_http_finding_status(finding: &HttpProbeFinding) -> String {
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

pub fn human_readable_size(length: &str) -> String {
    if let Ok(value) = length.parse::<u64>() {
        return format_bytes(value);
    }

    length.to_string()
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

fn http_table_header_row(widths: &HttpTableDimensions) -> String {
    format!(
        "{:<url_width$}  {:>status_width$}  {:>length_width$}  {:<title_width$}",
        "URL",
        "状态",
        "大小",
        "标题",
        url_width = widths.url,
        status_width = widths.status,
        length_width = widths.length,
        title_width = widths.title
    )
}

fn http_table_separator_row(widths: &HttpTableDimensions, accessible: bool) -> String {
    let separator_char = if accessible { '-' } else { '─' };
    let url_rule: String = std::iter::repeat(separator_char).take(widths.url).collect();
    let status_rule: String = std::iter::repeat(separator_char)
        .take(widths.status)
        .collect();
    let length_rule: String = std::iter::repeat(separator_char)
        .take(widths.length)
        .collect();
    let title_rule: String = std::iter::repeat(separator_char)
        .take(widths.title)
        .collect();

    format!(
        "{url_rule}  {status_rule}  {length_rule}  {title_rule}",
        url_rule = url_rule,
        status_rule = status_rule,
        length_rule = length_rule,
        title_rule = title_rule
    )
}

fn format_http_table_row(
    url_display: &str,
    title_display: &str,
    finding: &HttpProbeFinding,
    widths: &HttpTableDimensions,
    accessible: bool,
) -> String {
    let url_column = format!("{:<width$}", url_display, width = widths.url);
    let url_column = if accessible {
        url_column
    } else {
        format!("{}", url_column.cyan())
    };

    let status_column = format!("{:>width$}", finding.status_code, width = widths.status);
    let status_column = stylize_status(status_column, finding.status_code, accessible);

    let length_column = format!("{:>width$}", finding.length_display, width = widths.length);
    let length_column = if accessible {
        length_column
    } else {
        format!("{}", length_column.yellow())
    };

    let title_column = format!("{:<width$}", title_display, width = widths.title);
    let title_column = if accessible {
        title_column
    } else {
        format!("{}", title_column.white())
    };

    format!(
        "{url_column}  {status_column}  {length_column}  {title_column}",
        url_column = url_column,
        status_column = status_column,
        length_column = length_column,
        title_column = title_column
    )
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
