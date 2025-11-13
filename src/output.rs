use colorful::{Color, Colorful};
use console::Term;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressFinish, ProgressStyle};

const PROGRESS_TEMPLATE: &str =
    "{spinner:.green} {msg:<20} {wide_bar:.cyan/blue} {percent:>3}% | {pos:>5}/{len:<5} | {eta_precise}";
const PROGRESS_TEMPLATE_ACCESSIBLE: &str =
    "{msg:<20} [{bar:40}] {percent:>3}% | {pos:>5}/{len:<5} | {eta_precise}";
const PROGRESS_CHARS: &str = "█▓░";
const PROGRESS_CHARS_ACCESSIBLE: &str = "=>-";
const TICK_CHARS: &str = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";
const TICK_CHARS_ACCESSIBLE: &str = "-\\|/";

fn build_progress_style(accessible: bool) -> ProgressStyle {
    let template = if accessible {
        PROGRESS_TEMPLATE_ACCESSIBLE
    } else {
        PROGRESS_TEMPLATE
    };

    let style =
        ProgressStyle::with_template(template).unwrap_or_else(|_| ProgressStyle::default_bar());

    if accessible {
        style
            .progress_chars(PROGRESS_CHARS_ACCESSIBLE)
            .tick_chars(TICK_CHARS_ACCESSIBLE)
    } else {
        style.progress_chars(PROGRESS_CHARS).tick_chars(TICK_CHARS)
    }
}

pub fn create_progress_bar(
    total: u64,
    message: &str,
    accessible: bool,
    draw_hz: u8,
) -> ProgressBar {
    let progress_bar = ProgressBar::new(total).with_finish(ProgressFinish::AndClear);

    if Term::stderr().is_term() {
        progress_bar.set_style(build_progress_style(accessible));
        progress_bar.set_draw_target(ProgressDrawTarget::stderr_with_hz(draw_hz));
    } else {
        progress_bar.set_draw_target(ProgressDrawTarget::hidden());
    }

    progress_bar.set_message(message.to_string());
    progress_bar
}

pub fn format_section_heading(text: impl Into<String>, accessible: bool) -> String {
    let text = text.into();
    if accessible {
        text
    } else {
        text.color(Color::Cyan).bold().to_string()
    }
}

pub fn format_list_entry(text: impl Into<String>, accessible: bool) -> String {
    let text = text.into();
    if accessible {
        text
    } else {
        text.color(Color::Magenta).bold().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_heading_based_on_accessibility() {
        assert_eq!(format_section_heading("Heading", true), "Heading");
        assert!(format_section_heading("Heading", false).contains("Heading"));
    }

    #[test]
    fn formats_list_entry_based_on_accessibility() {
        assert_eq!(format_list_entry("Entry", true), "Entry");
        assert!(format_list_entry("Entry", false).contains("Entry"));
    }

    #[test]
    fn creates_progress_bar_with_message() {
        let pb = create_progress_bar(10, "Test", false, 1);
        assert_eq!(pb.length(), Some(10));
        assert_eq!(pb.message(), "Test");
    }
}
