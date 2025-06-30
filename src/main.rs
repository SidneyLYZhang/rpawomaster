//  ____  ____     __        __    __  __           _
// |  _ \|  _ \ __ \ \      / /__ |  \/  | __ _ ___| |_ ___ _ __ 
// | |_) | |_) / _` \ \ /\ / / _ \| |\/| |/ _` / __| __/ _ \ '__|
// |  _ <|  __/ (_| |\ V  V / (_) | |  | | (_| \__ \ ||  __/ |   
// |_| \_\_|   \__,_| \_/\_/ \___/|_|  |_|\__,_|___/\__\___|_|   
//
// Auther : Sidney Zhang <zly@lyzhang.me>
// Date : 2025-06-30
// Version : 0.1.0
// License : Mulan PSL v2
//
// A secure password manager written in Rust.

use clap::Parser;
use rand::seq::SliceRandom;
use rand::rngs::OsRng;
use zxcvbn::zxcvbn;
use std::collections::HashSet;
use rsa::RsaPrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::pkcs8::LineEnding;
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use aes_gcm::Nonce;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use hmac::Hmac;
use serde::{Serialize, Deserialize};
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use dirs::config_dir;
use rpassword::read_password;
use hex::encode;
use rand::Rng;
use std::io::{self, Write};
use chrono::Local;

#[derive(Debug, Parser)]
#[command(name = "rpawomaster")]
#[command(about = "A secure password manager written in Rust", long_about = None)]
enum Cli {
    /// Initialize a new password vault
    Init {
        /// Path to configuration file to import
        #[arg(short, long)]
        import: Option<String>,
    },

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

#[derive(Debug, Serialize, Deserialize)]
struct ConfigFile {
    username: String,
    encrypted_private_key: String,
    public_key: String,
    vault_name: String,
    vault_path: String,
    default_vault: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultMetadata {
    name: String,
    path: String,
    created_at: String,
    last_modified: String,
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

fn read_password_from_stdin(prompt: &str) -> Result<String, String> {
    print!("{}", prompt);
    io::stdout().flush().map_err(|e| format!("Failed to flush output: {}", e))?;
    read_password().map_err(|e| format!("Failed to read password: {}", e))
}

fn generate_rsa_keypair() -> Result<(String, String), String> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| format!("Failed to generate RSA key pair: {}", e))?;
    let public_key = private_key.to_public_key();

    let private_key_pem = private_key.to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("Failed to serialize private key: {}", e))?;
    let public_key_pem = public_key.to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("Failed to serialize public key: {}", e))?;

    Ok((private_key_pem, public_key_pem))
}

fn encrypt_private_key(private_key: &str, core_password: &str) -> Result<String, String> {
    // 生成随机盐和nonce
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    let mut rng = OsRng;
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 使用PBKDF2派生密钥
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(
        core_password.as_bytes(),
        &salt,
        100000,
        &mut key
    );

    // 加密私钥
    let cipher = Aes256Gcm::new(&key.into());
    let ciphertext = cipher.encrypt(nonce, private_key.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // 组合盐、nonce和密文并编码为hex
    let mut result = Vec::new();
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(encode(&result))
}

fn get_config_dir() -> Result<PathBuf, String> {
    config_dir()
        .ok_or_else(|| "Could not determine configuration directory".to_string())?
        .join("rPaWoMaster")
}

fn interactive_init() -> Result<(), String> {
    // 获取用户输入
    print!("Enter username: ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut username = String::new();
    io::stdin().read_line(&mut username).map_err(|e| e.to_string())?;
    let username = username.trim();
    if username.is_empty() {
        return Err("Username cannot be empty".to_string());
    }

    let core_password = read_password_from_stdin("Enter core password: ")?;
    let confirm_password = read_password_from_stdin("Confirm core password: ")?;
    if core_password != confirm_password {
        return Err("Passwords do not match".to_string());
    }

    // 评估密码强度
    let (rating, score, feedback) = assess_password_strength(&core_password);
    println!("Core password strength: {} (score: {}/4)", rating, score);
    if score < 3 {
        println!("Warning: Weak core password. {}", feedback);
        print!("Continue with weak password? [y/N]: ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut response = String::new();
        io::stdin().read_line(&mut response).map_err(|e| e.to_string())?;
        if !response.trim().eq_ignore_ascii_case("y") {
            return Err("Initialization cancelled".to_string());
        }
    }

    print!("Enter vault name (default: MyVault): ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut vault_name = String::new();
    io::stdin().read_line(&mut vault_name).map_err(|e| e.to_string())?;
    let vault_name = vault_name.trim();
    let vault_name = if vault_name.is_empty() { "MyVault" } else { vault_name };

    print!("Enter vault save location (default: {{config_dir}}/vaults/{}): ", vault_name);
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut vault_path = String::new();
    io::stdin().read_line(&mut vault_path).map_err(|e| e.to_string())?;
    let vault_path = vault_path.trim();
    let default_vault_path = get_config_dir()?
        .join("vaults")
        .join(vault_name);
    let vault_path = if vault_path.is_empty() {
        default_vault_path.to_string_lossy().into_owned()
    } else {
        vault_path.to_string()
    };

    // 创建密码库目录
    let vault_path_buf = PathBuf::from(&vault_path);
    fs::create_dir_all(&vault_path_buf)
        .map_err(|e| format!("Failed to create vault directory: {}", e))?;

    // 生成RSA密钥对
    println!("Generating RSA key pair...");
    let (private_key_pem, public_key_pem) = generate_rsa_keypair()?;

    // 加密私钥
    println!("Encrypting private key...");
    let encrypted_private_key = encrypt_private_key(&private_key_pem, &core_password)?;

    // 创建配置文件
    let config = ConfigFile {
        username: username.to_string(),
        encrypted_private_key,
        public_key: public_key_pem,
        vault_name: vault_name.to_string(),
        vault_path: vault_path.clone(),
        default_vault: true,
    };

    // 保存配置文件
    let config_dir = get_config_dir()?;
    fs::create_dir_all(&config_dir)
        .map_err(|e| format!("Failed to create config directory: {}", e))?;
    let config_file_path = config_dir.join(format!("{}.json", username));
    let config_file = fs::File::create(&config_file_path)
        .map_err(|e| format!("Failed to create config file: {}", e))?;
    serde_json::to_writer_pretty(config_file, &config)
        .map_err(|e| format!("Failed to write config file: {}", e))?;

    // 创建密码库元数据
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let metadata = VaultMetadata {
        name: vault_name.to_string(),
        path: vault_path,
        created_at: now.clone(),
        last_modified: now,
    };
    let metadata_path = vault_path_buf.join("metadata.json");
    let metadata_file = fs::File::create(&metadata_path)
        .map_err(|e| format!("Failed to create metadata file: {}", e))?;
    serde_json::to_writer_pretty(metadata_file, &metadata)
        .map_err(|e| format!("Failed to write metadata file: {}", e))?;

    Ok(())
}

fn import_config(import_path: &str) -> Result<(), String> {
    // 读取导入的配置文件
    let config_data = fs::read_to_string(import_path)
        .map_err(|e| format!("Failed to read import file: {}", e))?;
    let config: ConfigFile = serde_json::from_str(&config_data)
        .map_err(|e| format!("Invalid config file format: {}", e))?;

    // 确保配置目录存在
    let config_dir = get_config_dir()?;
    fs::create_dir_all(&config_dir)
        .map_err(|e| format!("Failed to create config directory: {}", e))?;

    // 保存配置文件
    let config_file_path = config_dir.join(format!("{}.json", config.username));
    if config_file_path.exists() {
        return Err(format!("Config file for user '{}' already exists", config.username));
    }

    let config_file = fs::File::create(&config_file_path)
        .map_err(|e| format!("Failed to create config file: {}", e))?;
    serde_json::to_writer_pretty(config_file, &config)
        .map_err(|e| format!("Failed to write config file: {}", e))?;

    // 确保密码库目录存在
    let vault_path = PathBuf::from(&config.vault_path);
    fs::create_dir_all(&vault_path)
        .map_err(|e| format!("Failed to create vault directory: {}", e))?;

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    match cli {
        Cli::Init { import } => {
            if let Some(import_path) = import {
                match import_config(&import_path) {
                    Ok(_) => println!("Successfully imported password vault from {}", import_path),
                    Err(e) => eprintln!("Failed to import vault: {}", e),
                }
            } else {
                match interactive_init() {
                    Ok(_) => println!("Password vault initialized successfully"),
                    Err(e) => eprintln!("Initialization failed: {}", e),
                }
            }
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
