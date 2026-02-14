use crate::passgen;

pub fn test_password(
    password: String,
    check_url_safe: bool,
    check_confusion: bool,
) -> Result<(), String> {
    let (rating, score, feedback) = passgen::assess_password_strength(&password)?;
    println!("Password strength: {} (score: {}/4)", rating, score);
    if !feedback.is_empty() {
        println!("Suggestions: {}", feedback);
    }

    if check_url_safe {
        let is_safe = passgen::check_url_safe(&password);
        println!("URL-safe: {}", if is_safe { "Yes" } else { "No" });
    }

    if check_confusion {
        let confusing = passgen::check_confusing_chars(&password);
        if !confusing.is_empty() {
            println!("Potentially confusing characters: {:?}", confusing);
        } else {
            println!("No confusing characters detected");
        }
    }
    Ok(())
}
