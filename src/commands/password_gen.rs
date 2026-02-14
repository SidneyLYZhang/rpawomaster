use crate::passgen::{self, Capitalization, evaluate_and_display_password_strength};

pub fn generate_random(
    length: usize,
    no_uppercase: bool,
    no_lowercase: bool,
    no_numbers: bool,
    no_special: bool,
    url_safe: bool,
    avoid_confusion: bool,
) -> Result<(), String> {
    let options = passgen::PasswordOptions {
        length,
        include_uppercase: !no_uppercase,
        include_lowercase: !no_lowercase,
        include_numbers: !no_numbers,
        include_special: !no_special,
        url_safe,
        avoid_confusion,
    };
    let password = passgen::generate_password(&options)
        .map_err(|e| format!("Failed to generate password: {}", e))?;
    println!("Generated random password: {}", password);
    evaluate_and_display_password_strength(&password)?;
    Ok(())
}

pub fn generate_memorable(
    words: usize,
    separator: char,
    include_numbers: bool,
    capitalization: Capitalization,
) -> Result<(), String> {
    let options = passgen::MemorablePasswordOptions {
        word_count: words,
        separator,
        include_numbers,
        capitalization,
    };
    let password = passgen::generate_memorable_password(&options)
        .map_err(|e| format!("Failed to generate memorable password: {}", e))?;
    println!("Generated memorable password: {}", password);
    evaluate_and_display_password_strength(&password)?;
    Ok(())
}
