//! The terminal banner: Matsya, the horned golden fish, and the wordmark.
//!
//! Shown when matsya runs without a command and above `--help`. Colors use
//! the 256-color palette; they are dropped when output is not a terminal or
//! `NO_COLOR` is set, so scripts and CI logs get plain text.

use std::io::IsTerminal;

/// Palette (xterm-256): the same golds, orange and teal as the logo.
const HORN: u8 = 222;
const GOLD: u8 = 220;
const SCALE: u8 = 172;
const FIN: u8 = 208;
const WAVE: [u8; 2] = [37, 31];
const WORD: [u8; 4] = [229, 221, 214, 208];
const TAG: u8 = 250;
const MINT: u8 = 79;
const DIM: u8 = 244;

/// Color segments: (text, color); 0 = no color, 1 = bold default color.
type Line = &'static [(&'static str, u8)];

const FISH: [Line; 5] = [
    &[("              ", 0), ("__", GOLD), ("/)", HORN)],
    &[("   ", 0), ("\\`.", FIN), ("  ", 0), (".-''``    ``'-.", GOLD)],
    &[("    ", 0), (") >", FIN), ("(  ", GOLD), ("((( (((", SCALE), ("    ", 0), ("●", 1), (" >", GOLD)],
    &[("   ", 0), ("/.'", FIN), ("  ", 0), ("'-..______..-'", GOLD)],
    &[("  ", 0), ("~^~^~^~^~^~^~^~^~^~^~^~^~", 2)],
];

/// "matsya" in half-block letters (generated from 5x6 pixel glyphs).
const WORDMARK: [&str; 3] = [
    "▄▄ ▄▄   ▄▄▄  ▄▄█▄▄  ▄▄▄▄ ▄   ▄  ▄▄▄",
    "█ █ █   ▄▄▄█   █   ▀▄▄▄  ▀▄▄▄█  ▄▄▄█",
    "▀ ▀ ▀  ▀▄▄▄█   ▀▄▄ ▄▄▄▄▀  ▄▄▄▀ ▀▄▄▄█",
];

fn fg(c: u8, s: &str, color: bool) -> String {
    match (color, c) {
        (false, _) | (_, 0) => s.to_string(),
        (true, 1) => format!("\x1b[1m{s}\x1b[0m"),
        (true, c) => format!("\x1b[38;5;{c}m{s}\x1b[0m"),
    }
}

fn width(line: Line) -> usize {
    line.iter().map(|(t, _)| t.chars().count()).sum()
}

fn fish_line(line: Line, color: bool) -> String {
    line.iter()
        .map(|(t, c)| {
            if *c == 2 {
                // waves alternate two teals
                t.chars().enumerate().map(|(i, ch)| fg(WAVE[i % 2], &ch.to_string(), color)).collect()
            } else {
                fg(*c, t, color)
            }
        })
        .collect()
}

/// Gold-to-orange gradient across the wordmark, in four bands.
fn wordmark_line(s: &str, color: bool) -> String {
    if !color {
        return s.to_string();
    }
    let n = s.chars().count().max(1);
    let mut out = String::new();
    let mut band = usize::MAX;
    for (i, ch) in s.chars().enumerate() {
        let b = i * WORD.len() / n;
        if b != band {
            if band != usize::MAX {
                out.push_str("\x1b[0m");
            }
            out.push_str(&format!("\x1b[1;38;5;{}m", WORD[b]));
            band = b;
        }
        out.push(ch);
    }
    out.push_str("\x1b[0m");
    out
}

/// The banner as a block of text (no trailing newline).
pub fn render(color: bool) -> String {
    let pad = FISH.iter().map(|l| width(l)).max().unwrap_or(0) + 3;
    let tagline = format!(
        "{}{}{}",
        fg(TAG, "lock files & ", color),
        fg(MINT, "SBOMs", color),
        fg(TAG, " for OS package managers", color)
    );
    let mut out = Vec::new();
    for (i, line) in FISH.iter().enumerate() {
        let left = fish_line(line, color) + &" ".repeat(pad - width(line));
        let right = match i {
            1..=3 => wordmark_line(WORDMARK[i - 1], color),
            4 => tagline.clone(),
            _ => String::new(),
        };
        out.push(format!("{left}{right}").trim_end().to_string());
    }
    out.push(format!(
        "{}{}",
        " ".repeat(pad),
        fg(DIM, &format!("v{} · github.com/dmdhrumilmistry/matsya", env!("CARGO_PKG_VERSION")), color)
    ));
    out.join("\n")
}

/// Colors on stdout: a terminal, and NO_COLOR unset (https://no-color.org).
pub fn color_stdout() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").map_or(true, |v| v.is_empty())
}

/// What `matsya` with no command prints.
pub fn welcome(color: bool) -> String {
    let cmd = |c: &str, d: &str| format!("  {}  {}", fg(GOLD, &format!("{c:<19}"), color), d);
    [
        String::new(),
        render(color),
        String::new(),
        cmd("matsya lock", "snapshot this machine into matsya.lock.json"),
        cmd("matsya check", "exit 1 if the machine drifted from the lock"),
        cmd("matsya sbom", "CycloneDX or SPDX SBOM from the lock"),
        cmd("sudo matsya apply", "rebuild the locked state on this machine"),
        String::new(),
        format!("  Run {} for every command and option.", fg(MINT, "matsya --help", color)),
        String::new(),
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_banner_has_no_escapes_and_aligns() {
        let plain = render(false);
        assert!(!plain.contains('\x1b'));
        let lines: Vec<&str> = plain.lines().collect();
        assert_eq!(lines.len(), 6);
        // wordmark and tagline start in the same column
        let col = |l: &str, needle: &str| l.find(needle).map(|b| l[..b].chars().count());
        assert_eq!(col(lines[1], "▄▄ ▄▄"), col(lines[4], "lock files"));
        assert!(plain.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn colored_banner_strips_to_plain() {
        let colored = render(true);
        assert!(colored.contains("\x1b[38;5;"));
        let mut stripped = String::new();
        let mut in_esc = false;
        for ch in colored.chars() {
            match (in_esc, ch) {
                (false, '\x1b') => in_esc = true,
                (true, 'm') => in_esc = false,
                (true, _) => {}
                (false, c) => stripped.push(c),
            }
        }
        assert_eq!(stripped, render(false));
    }
}
