use colorful::Colorful;

#[derive(Clone, Copy)]
pub struct OutputTheme {
    accessible: bool,
}

impl OutputTheme {
    pub const fn new(accessible: bool) -> Self {
        Self { accessible }
    }

    pub fn progress_template(self) -> &'static str {
        if self.accessible {
            "{msg} [{bar:40}] {pos:>5}/{len:<5} {percent:>3}%"
        } else {
            "{msg} │{bar:40.cyan/blue}│ {pos:>5}/{len:<5} {percent:>3}%"
        }
    }

    pub fn progress_chars(self) -> &'static str {
        if self.accessible {
            "=>-"
        } else {
            "█▓░"
        }
    }

    pub fn heading(self, text: &str) -> String {
        if self.accessible {
            text.to_string()
        } else {
            text.cyan().bold().to_string()
        }
    }

    pub fn bullet_item(self, text: &str) -> String {
        if self.accessible {
            text.to_string()
        } else {
            text.purple().bold().to_string()
        }
    }

    pub fn table_header(self, row: String) -> String {
        if self.accessible {
            row
        } else {
            row.white().bold().to_string()
        }
    }

    pub fn separator_char(self) -> char {
        if self.accessible {
            '-'
        } else {
            '─'
        }
    }

    pub fn url_column(self, value: String) -> String {
        if self.accessible {
            value
        } else {
            value.cyan().to_string()
        }
    }

    pub fn length_column(self, value: String) -> String {
        if self.accessible {
            value
        } else {
            value.yellow().to_string()
        }
    }

    pub fn title_column(self, value: String) -> String {
        if self.accessible {
            value
        } else {
            value.white().to_string()
        }
    }

    pub fn status_column(self, value: String, code: u16) -> String {
        if self.accessible {
            return value;
        }

        if (200..=299).contains(&code) {
            value.green().bold().to_string()
        } else if (300..=399).contains(&code) {
            value.yellow().bold().to_string()
        } else if (400..=599).contains(&code) {
            value.red().bold().to_string()
        } else {
            value.white().to_string()
        }
    }
}
