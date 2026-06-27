//! Color themes for the TUI.

use ratatui::style::Color;

pub struct Theme {
    pub fg: Color,
    pub accent: Color,
    pub muted: Color,
    pub header: Color,
    pub selection_bg: Color,
    pub muted_selection_bg: Color,
    /// Cell styling by kind.
    pub code: Color,
    pub link: Color,
    pub num: Color,
    pub error: Color,
}

impl Theme {
    pub fn dark() -> Self {
        Theme {
            fg: Color::Gray,
            accent: Color::Cyan,
            muted: Color::DarkGray,
            header: Color::Yellow,
            selection_bg: Color::Rgb(40, 60, 80),
            muted_selection_bg: Color::Rgb(45, 45, 45),
            code: Color::White,
            link: Color::Blue,
            num: Color::Green,
            error: Color::Red,
        }
    }

    pub fn light() -> Self {
        Theme {
            fg: Color::Black,
            accent: Color::Blue,
            muted: Color::Gray,
            header: Color::Magenta,
            selection_bg: Color::Rgb(200, 220, 240),
            muted_selection_bg: Color::Rgb(225, 225, 225),
            code: Color::Black,
            link: Color::Blue,
            num: Color::Rgb(0, 120, 0),
            error: Color::Rgb(180, 0, 0),
        }
    }
}
