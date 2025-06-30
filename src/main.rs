use clap::Parser;
use rand::seq::SliceRandom;
use rand::rngs::OsRng;
use zxcvbn::zxcvbn;
use std::collections::HashSet;

#[derive(Debug, Parser)]
#[command(name = "rpawomaster")]
#[command(about = "A secure password manager written in Rust", long_about = None)]
enum Cli {
    /// Initialize a new password vault
    Init,

    /// Generate a new random password
    Gen(GenArgs),

    /// Add a password to the vault
    Add,

    /// Update an existing password
    Update,

    /// Search passwords in the vault
    Search,

    /// Test password strength and properties
    Testpass(TestpassArgs),
}

#[derive(Debug, Parser)]
struct TestpassArgs {
    /// Password to test
    password: String,

    /// Check if password is URL-safe
    #[arg(short = 's', long, default_value_t = false)]
    check_url_safe: bool,

    /// Check for visually confusing characters
    #[arg(short = 'c', long, default_value_t = false)]
    check_confusion: bool,
}

#[derive(Debug, Parser)]
struct GenArgs {
    /// Length of the password
    #[arg(short, long, default_value_t = 12)]
    length: usize,

    /// Exclude uppercase letters
    #[arg(long, default_value_t = false)]
    no_uppercase: bool,

    /// Exclude lowercase letters
    #[arg(long, default_value_t = false)]
    no_lowercase: bool,

    /// Exclude numbers
    #[arg(long, default_value_t = false)]
    no_numbers: bool,

    /// Exclude special characters
    #[arg(long, default_value_t = false)]
    no_special: bool,

    /// Make password URL-safe
    #[arg(short = 's', long, default_value_t = false)]
    url_safe: bool,

    /// Avoid visually confusing characters
    #[arg(short = 'c', long, default_value_t = false)]
    avoid_confusion: bool,
}

struct PasswordOptions {
    length: usize,
    include_uppercase: bool,
    include_lowercase: bool,
    include_numbers: bool,
    include_special: bool,
    url_safe: bool,
    avoid_confusion: bool,
}

impl From<GenArgs> for PasswordOptions {
    fn from(args: GenArgs) -> Self {
        Self {
            length: args.length,
            include_uppercase: !args.no_uppercase,
            include_lowercase: !args.no_lowercase,
            include_numbers: !args.no_numbers,
            include_special: !args.no_special,
            url_safe: args.url_safe,
            avoid_confusion: args.avoid_confusion,
        }
    }
}

fn generate_password(options: &PasswordOptions) -> Result<String, String> {
    // Define base character sets
    let mut uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string();
    let mut lowercase = "abcdefghijklmnopqrstuvwxyz".to_string();
    let mut numbers = "0123456789".to_string();
    let mut special = if options.url_safe {
        "-._~" .to_string()
    } else {
        "!@#$%^&*()_+-=[]{}|;:,.<>?~" .to_string()
    };

    // Remove confusing characters if requested
    if options.avoid_confusion {
        let confusing_chars: HashSet<char> = ['l', 'I', '1', 'O', '0', 'o'].iter().cloned().collect();
        uppercase.retain(|c| !confusing_chars.contains(&c));
        lowercase.retain(|c| !confusing_chars.contains(&c));
        numbers.retain(|c| !confusing_chars.contains(&c));
        special.retain(|c| !confusing_chars.contains(&c));
    }

    // Collect required character sets and check availability
    let mut required_sets = Vec::new();
    if options.include_uppercase {
        if uppercase.is_empty() {
            return Err("Uppercase character set is empty after removing confusing characters".to_string());
        }
        required_sets.push(uppercase.chars().collect::<Vec<_>>());
    }
    if options.include_lowercase {
        if lowercase.is_empty() {
            return Err("Lowercase character set is empty after removing confusing characters".to_string());
        }
        required_sets.push(lowercase.chars().collect::<Vec<_>>());
    }
    if options.include_numbers {
        if numbers.is_empty() {
            return Err("Numbers character set is empty after removing confusing characters".to_string());
        }
        required_sets.push(numbers.chars().collect::<Vec<_>>());
    }
    if options.include_special {
        if special.is_empty() {
            return Err("Special character set is empty after removing confusing characters".to_string());
        }
        required_sets.push(special.chars().collect::<Vec<_>>());
    }

    // Validate at least one character set is selected
    if required_sets.is_empty() {
        return Err("At least one character set must be included".to_string());
    }

    // Validate password length is sufficient for required sets
    if options.length < required_sets.len() {
        return Err(format!("Password length must be at least {} to include all required character sets", required_sets.len()));
    }

    // Build the combined character pool
    let mut char_pool = String::new();
    if options.include_uppercase { char_pool.push_str(&uppercase); }
    if options.include_lowercase { char_pool.push_str(&lowercase); }
    if options.include_numbers { char_pool.push_str(&numbers); }
    if options.include_special { char_pool.push_str(&special); }
    let all_chars: Vec<char> = char_pool.chars().collect();

    // Generate password with at least one character from each required set
    let mut rng = OsRng::default();
    let mut password_chars = Vec::with_capacity(options.length);

    // Add one character from each required set
    for chars in &required_sets {
        password_chars.push(*chars.choose(&mut rng).unwrap());
    }

    // Add remaining characters from combined pool
    for _ in 0..(options.length - required_sets.len()) {
        password_chars.push(*all_chars.choose(&mut rng).unwrap());
    }

    // Shuffle the characters to avoid predictable pattern
    password_chars.shuffle(&mut rng);

    Ok(password_chars.into_iter().collect())
}

fn check_url_safe(password: &str) -> bool {
    password.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))
}

fn check_confusing_chars(password: &str) -> Vec<char> {
    let confusing_chars = ['l', 'I', '1', 'O', '0', 'o'];
    password.chars().filter(|c| confusing_chars.contains(c)).collect()
}

fn assess_password_strength(password: &str) -> (String, u8, String) {
    let strength_result = zxcvbn(password, &[]);
    let score = strength_result.score();
    let feedback = strength_result.feedback().map_or_else(
        || String::new(),
        |f| f.suggestions().iter().map(|s| s.to_string()).collect::<Vec<_>>().join(" ")
    );

    // 确定安全评级
    let rating = match score {
        zxcvbn::Score::Zero => "极弱",
        zxcvbn::Score::One => "弱",
        zxcvbn::Score::Two => "中等",
        zxcvbn::Score::Three => "强",
        zxcvbn::Score::Four => "极强",
        _ => "未知",
    }.to_string();

    (rating, score as u8, feedback)
}

fn main() {
    let cli = Cli::parse();

    match cli {
        Cli::Init => {
            println!("Initializing new password vault...");
            // TODO: Implement vault initialization
        }
        Cli::Gen(args) => {
            let options = PasswordOptions::from(args);
            match generate_password(&options) {
                Ok(password) => {
                let (rating, score, _feedback) = assess_password_strength(&password);
                println!("Generated password: {}", password);
                println!("Password strength: {} (score: {}/4)", rating, score);
            },
                Err(e) => eprintln!("Error generating password: {}", e),
            }
        }
        Cli::Add => {
            println!("Adding password to vault...");
            // TODO: Implement add functionality
        }
        Cli::Update => {
            println!("Updating password...");
            // TODO: Implement update functionality
        }
        Cli::Testpass(args) => {
            let (rating, score, feedback) = assess_password_strength(&args.password);
            let url_safe = check_url_safe(&args.password);
            let confusing_chars = check_confusing_chars(&args.password);

            println!("Password: {}", args.password);
            println!("Strength rating: {} (score: {}/4)", rating, score);
            if !feedback.is_empty() {
                println!("Improvement suggestions: {}", feedback);
            }
            if args.check_url_safe {
                println!("URL-safe: {}", if url_safe { "Yes" } else { "No" });
            }
            if args.check_confusion {
                if confusing_chars.is_empty() {
                    println!("No visually confusing characters");
                } else {
                    println!("Visually confusing characters: {:?}", confusing_chars);
                }
            }
        },
        Cli::Search => {
            println!("Searching passwords...");
            // TODO: Implement search functionality
        }
    }
}
