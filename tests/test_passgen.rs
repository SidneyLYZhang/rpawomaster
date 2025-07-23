use rpawomaster::passgen::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password_default_options() {
        let options = PasswordOptions::default();
        let password = generate_password(&options).unwrap();
        assert_eq!(password.len(), 16);
        assert!(password.chars().any(|c| c.is_uppercase()));
        assert!(password.chars().any(|c| c.is_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(password.chars().any(|c| !c.is_alphanumeric()));
    }

    #[test]
    fn test_generate_password_custom_options() {
        let options = PasswordOptions {
            length: 20,
            include_uppercase: false,
            include_lowercase: true,
            include_numbers: true,
            include_special: false,
            url_safe: true,
            avoid_confusion: true,
        };
        let password = generate_password(&options).unwrap();
        assert_eq!(password.len(), 20);
        assert!(!password.chars().any(|c| c.is_uppercase()));
        assert!(password.chars().any(|c| c.is_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(!password.chars().any(|c| !c.is_alphanumeric()));
    }

    #[test]
    fn test_generate_password_minimum_length() {
        let options = PasswordOptions {
            length: 4,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_special: true,
            ..Default::default()
        };
        let password = generate_password(&options).unwrap();
        assert_eq!(password.len(), 4);
    }

    #[test]
    fn test_generate_password_invalid_options() {
        let options = PasswordOptions {
            length: 3,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_special: true,
            ..Default::default()
        };
        let result = generate_password(&options);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_memorable_password_default_options() {
        let options = MemorablePasswordOptions::default();
        let password = generate_memorable_password(&options).unwrap();
        let parts: Vec<&str> = password.split('-').collect();
        assert_eq!(parts.len(), 4);
        parts.iter().for_each(|part| {
            assert!(part.chars().next().unwrap().is_uppercase());
            assert!(part[1..].chars().all(|c| c.is_lowercase()));
        });
    }

    #[test]
    fn test_generate_memorable_password_with_numbers() {
        let options = MemorablePasswordOptions {
            include_numbers: true,
            ..Default::default()
        };
        let password = generate_memorable_password(&options).unwrap();
        let parts: Vec<&str> = password.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts[4].chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_memorable_password_custom_separator() {
        let options = MemorablePasswordOptions {
            separator: '_',
            ..Default::default()
        };
        let password = generate_memorable_password(&options).unwrap();
        assert!(password.contains('_'));
        assert!(!password.contains('-'));
    }

    #[test]
    fn test_generate_memorable_password_no_capitalization() {
        let options = MemorablePasswordOptions {
            capitalization: Capitalization::NoCapitalization,
            ..Default::default()
        };
        let password = generate_memorable_password(&options).unwrap();
        assert!(password.chars().all(|c| c.is_lowercase() || c == '-'));
    }

    #[test]
    fn test_generate_memorable_password_invalid_word_count() {
        let options = MemorablePasswordOptions {
            word_count: 0,
            ..Default::default()
        };
        let result = generate_memorable_password(&options);
        assert!(result.is_err());
    }
}