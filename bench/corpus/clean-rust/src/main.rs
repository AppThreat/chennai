use std::io::{self, Write};

/// A simple greeting utility. No security-sensitive operations.
fn main() {
    print!("Enter your name: ");
    io::stdout().flush().unwrap();

    let mut name = String::new();
    io::stdin().read_line(&mut name).unwrap();
    let name = name.trim();

    println!("Hello, {}!", name);
}

/// Add two numbers safely using checked arithmetic.
fn safe_add(a: u32, b: u32) -> Option<u32> {
    a.checked_add(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_add() {
        assert_eq!(safe_add(1, 2), Some(3));
        assert_eq!(safe_add(u32::MAX, 1), None);
    }
}
