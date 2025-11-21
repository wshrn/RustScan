//! Utilities for terminal output during scanning.

/// Terminal User Interface Module for RustScan
/// Defines macros to use
#[macro_export]
macro_rules! warning {
    ($name:expr) => {
        $crate::tui::progress_println(format!(
            "{} {}",
            ansi_term::Colour::Red.bold().paint("[!]").to_string(),
            $name
        ));
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        // if not greppable then print, otherwise no else statement so do not print.
        if !$greppable {
            if $accessible {
                // Don't print the ascii art
                $crate::tui::progress_println($name.to_string());
            } else {
                $crate::tui::progress_println(format!(
                    "{} {}",
                    ansi_term::Colour::Red.bold().paint("[!]").to_string(),
                    $name
                ));
            }
        }
    };
}

#[macro_export]
macro_rules! detail {
    ($name:expr) => {
        $crate::tui::progress_println(format!(
            "{} {}",
            ansi_term::Colour::Blue.bold().paint("[~]").to_string(),
            $name
        ));
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        // if not greppable then print, otherwise no else statement so do not print.
        if !$greppable {
            if $accessible {
                // Don't print the ascii art
                $crate::tui::progress_println($name.to_string());
            } else {
                $crate::tui::progress_println(format!(
                    "{} {}",
                    ansi_term::Colour::Blue.bold().paint("[~]").to_string(),
                    $name
                ));
            }
        }
    };
}

#[macro_export]
macro_rules! output {
    ($name:expr) => {
        $crate::tui::progress_println(format!(
            "{} {}",
            ansi_term::Colour::RGB(0, 255, 9)
                .bold()
                .paint("[>]")
                .to_string(),
            $name
        ));
    };
    ($name:expr, $greppable:expr, $accessible:expr) => {
        // if not greppable then print, otherwise no else statement so do not print.
        if !$greppable {
            if $accessible {
                // Don't print the ascii art
                $crate::tui::progress_println($name.to_string());
            } else {
                $crate::tui::progress_println(format!(
                    "{} {}",
                    ansi_term::Colour::RGB(0, 255, 9)
                        .bold()
                        .paint("[>]")
                        .to_string(),
                    $name
                ));
            }
        }
    };
}

use indicatif::ProgressBar;
use once_cell::sync::OnceCell;
use std::sync::{Mutex, MutexGuard};

fn progress_bar_stack() -> &'static Mutex<Vec<ProgressBar>> {
    static STACK: OnceCell<Mutex<Vec<ProgressBar>>> = OnceCell::new();
    STACK.get_or_init(|| Mutex::new(Vec::new()))
}

fn lock_progress_bar_stack() -> MutexGuard<'static, Vec<ProgressBar>> {
    progress_bar_stack()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn current_progress_bar() -> Option<ProgressBar> {
    let stack = lock_progress_bar_stack();
    stack.last().cloned()
}

pub struct ProgressBarGuard;

impl Drop for ProgressBarGuard {
    fn drop(&mut self) {
        let mut stack = lock_progress_bar_stack();
        stack.pop();
    }
}

pub fn register_progress_bar(progress_bar: &ProgressBar) -> ProgressBarGuard {
    let mut stack = lock_progress_bar_stack();
    stack.push(progress_bar.clone());
    ProgressBarGuard
}

pub fn progress_println(message: impl Into<String>) {
    let text = message.into();
    if let Some(pb) = current_progress_bar() {
        pb.println(text);
    } else {
        ProgressBar::hidden().println(text);
    }
}
