//! REPL input state: an editable line, command history, and a scrollback of executed commands.

/// One executed REPL line and its outcome (shown in the scrollback).
#[derive(Debug, Clone)]
pub struct ReplEntry {
    pub input: String,
    pub status: String,
    pub ok: bool,
}

/// An open autocomplete popup: the candidate labels, the highlighted item, and the character
/// offset in the input line where the token being completed begins.
#[derive(Debug, Clone)]
pub struct Completion {
    pub items: Vec<String>,
    pub selected: usize,
    pub start: usize,
}

#[derive(Default)]
pub struct Repl {
    chars: Vec<char>,
    cursor: usize,
    pub entries: Vec<ReplEntry>,
    history: Vec<String>,
    hist_pos: Option<usize>,
    pub completion: Option<Completion>,
}

impl Repl {
    pub fn text(&self) -> String {
        self.chars.iter().collect()
    }

    /// Cursor position as a character offset (for rendering the caret).
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn insert(&mut self, c: char) {
        self.chars.insert(self.cursor, c);
        self.cursor += 1;
        self.hist_pos = None;
        self.completion = None;
    }

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.chars.remove(self.cursor - 1);
            self.cursor -= 1;
            self.hist_pos = None;
            self.completion = None;
        }
    }

    pub fn delete(&mut self) {
        if self.cursor < self.chars.len() {
            self.chars.remove(self.cursor);
            self.hist_pos = None;
            self.completion = None;
        }
    }

    pub fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn right(&mut self) {
        if self.cursor < self.chars.len() {
            self.cursor += 1;
        }
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.chars.len();
    }

    /// The current input characters (used to compute the token under the cursor).
    pub fn chars(&self) -> &[char] {
        &self.chars
    }

    pub fn is_completing(&self) -> bool {
        self.completion.is_some()
    }

    /// Open the autocomplete popup with `items`, where `start` is the char offset at which the
    /// token being completed begins.
    pub fn open_completion(&mut self, items: Vec<String>, start: usize) {
        if items.is_empty() {
            self.completion = None;
        } else {
            self.completion = Some(Completion { items, selected: 0, start });
        }
    }

    pub fn close_completion(&mut self) {
        self.completion = None;
    }

    pub fn completion_down(&mut self) {
        if let Some(c) = &mut self.completion
            && c.selected + 1 < c.items.len() {
                c.selected += 1;
            }
    }

    pub fn completion_up(&mut self) {
        if let Some(c) = &mut self.completion {
            c.selected = c.selected.saturating_sub(1);
        }
    }

    /// Accept the highlighted completion: replace the token `[start, cursor)` with the candidate.
    pub fn accept_completion(&mut self) {
        if let Some(c) = self.completion.take()
            && let Some(item) = c.items.get(c.selected) {
                let end = self.cursor.min(self.chars.len());
                let start = c.start.min(end);
                let replacement: Vec<char> = item.chars().collect();
                self.chars.splice(start..end, replacement.iter().copied());
                self.cursor = start + replacement.len();
                self.hist_pos = None;
            }
    }

    /// Replace the current line, placing the cursor at the end.
    pub fn set_text(&mut self, s: &str) {
        self.chars = s.chars().collect();
        self.cursor = self.chars.len();
        self.hist_pos = None;
    }

    pub fn clear(&mut self) {
        self.chars.clear();
        self.cursor = 0;
        self.hist_pos = None;
    }

    /// Record an executed command and its outcome; deduplicates consecutive identical inputs in the
    /// recall history.
    pub fn record(&mut self, input: &str, status: String, ok: bool) {
        if self.history.last().map(String::as_str) != Some(input) {
            self.history.push(input.to_string());
        }
        self.entries.push(ReplEntry { input: input.to_string(), status, ok });
        self.hist_pos = None;
    }

    /// Recall the previous command into the input line (Up arrow).
    pub fn recall_prev(&mut self) {
        if self.history.is_empty() {
            return;
        }
        let next = match self.hist_pos {
            None => self.history.len() - 1,
            Some(0) => 0,
            Some(i) => i - 1,
        };
        self.hist_pos = Some(next);
        let text = self.history[next].clone();
        self.chars = text.chars().collect();
        self.cursor = self.chars.len();
    }

    /// Recall the next command (Down arrow); past the newest entry clears the line.
    pub fn recall_next(&mut self) {
        match self.hist_pos {
            Some(i) if i + 1 < self.history.len() => {
                self.hist_pos = Some(i + 1);
                let text = self.history[i + 1].clone();
                self.chars = text.chars().collect();
                self.cursor = self.chars.len();
            }
            Some(_) => {
                self.hist_pos = None;
                self.clear();
            }
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_at_cursor() {
        let mut r = Repl::default();
        for c in "atom".chars() {
            r.insert(c);
        }
        assert_eq!(r.text(), "atom");
        assert_eq!(r.cursor(), 4);
        r.left();
        r.insert('X');
        assert_eq!(r.text(), "atoXm");
        r.backspace();
        assert_eq!(r.text(), "atom");
        r.home();
        r.delete();
        assert_eq!(r.text(), "tom");
    }

    #[test]
    fn history_recall_walks_back_and_forward() {
        let mut r = Repl::default();
        r.record("atom.file", "ok".into(), true);
        r.record("atom.method", "ok".into(), true);
        r.recall_prev();
        assert_eq!(r.text(), "atom.method");
        r.recall_prev();
        assert_eq!(r.text(), "atom.file");
        r.recall_next();
        assert_eq!(r.text(), "atom.method");
        r.recall_next();
        assert_eq!(r.text(), ""); // past newest clears
    }

    #[test]
    fn record_dedups_consecutive_inputs() {
        let mut r = Repl::default();
        r.record("atom.file", "ok".into(), true);
        r.record("atom.file", "ok".into(), true);
        r.recall_prev();
        r.recall_prev();
        // only one distinct history entry
        assert_eq!(r.text(), "atom.file");
        assert_eq!(r.entries.len(), 2);
    }

    #[test]
    fn accept_completion_replaces_token_under_cursor() {
        let mut r = Repl::default();
        r.set_text("atom.me");
        // Token "me" starts at offset 5.
        r.open_completion(vec!["member".into(), "method".into()], 5);
        assert!(r.is_completing());
        r.completion_down(); // select "method"
        r.accept_completion();
        assert_eq!(r.text(), "atom.method");
        assert_eq!(r.cursor(), 11);
        assert!(!r.is_completing());
    }

    #[test]
    fn editing_closes_completion_popup() {
        let mut r = Repl::default();
        r.set_text("atom.");
        r.open_completion(vec!["method".into()], 5);
        r.insert('m');
        assert!(!r.is_completing());
    }

    #[test]
    fn set_text_places_cursor_at_end() {
        let mut r = Repl::default();
        r.set_text("atom.call");
        assert_eq!(r.cursor(), 9);
        r.insert('s');
        assert_eq!(r.text(), "atom.calls");
    }
}
