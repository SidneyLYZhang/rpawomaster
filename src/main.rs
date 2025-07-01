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
use rsa::pkcs8::{EncodePrivateKey, DecodePrivateKey};
use rsa::pkcs8::EncodePublicKey;
use rsa::pkcs8::LineEnding;
use aes_gcm::Aes256Gcm;
use aes_gcm::AeadInPlace;
use aes_gcm::KeyInit;
use aes_gcm::Nonce;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use hmac::Hmac;
use serde::{Serialize, Deserialize};
use serde_json;
use std::fs;
use std::path::PathBuf;
use dirs::config_dir;
use rpassword::read_password;
use hex::encode;
use rand::RngCore;
use std::io::{self, Write};
use chrono::Local;

mod pwsmanager;

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
    Add {
        /// User to add password for
        #[arg(short, long)]
        user: Option<String>,
        
        /// Vault to add password to
        #[arg(short, long)]
        vault: Option<String>,
    },

    /// Update an existing password
    Update,

    /// list all existing passwords
    List,

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
struct VaultMetadata {
    name: String,
    path: String,
    created_at: String,
    last_modified: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Vault {
    name: String,
    path: String,
    is_default: bool,
    created_at: String,
    last_modified: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ConfigFile {
    username: String,
    encrypted_private_key: String,
    public_key: String,
    vaults: Vec<Vault>,
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

    Ok((private_key_pem.to_string(), public_key_pem.to_string()))
}

fn encrypt_private_key(private_key: &str, core_password: &str) -> Result<String, String> {
    // 生成随机盐和nonce
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    let mut rng = OsRng;
    let _ = rng.try_fill_bytes(&mut salt);
    let _ = rng.try_fill_bytes(&mut nonce_bytes);
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
    let mut data = private_key.as_bytes().to_vec();
    cipher.encrypt_in_place(nonce, b"", &mut data)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    let ciphertext = data;

    // 组合盐、nonce和密文并编码为hex
    let mut result = Vec::new();
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(encode(&result))
}

fn get_config_dir() -> Result<PathBuf, String> {
    match config_dir() {
        Some(path) => Ok(path.join("rpawomaster")),
        None => Err("Could not determine configuration directory".to_string()),
    }
}

fn decrypt_private_key(encrypted_private_key: &str, core_password: &str) -> Result<String, String> {
    // 解码hex字符串
    let data = hex::decode(encrypted_private_key)
        .map_err(|e| format!("Failed to decode encrypted private key: {}", e))?;
    
    // 提取盐、nonce和密文
    if data.len() < 16 + 12 {
        return Err("Invalid encrypted private key format".to_string());
    }
    let (salt, rest) = data.split_at(16);
    let (nonce_bytes, ciphertext) = rest.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // 派生密钥
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(
        core_password.as_bytes(),
        salt,
        100000,
        &mut key
    );
    
    // 解密
    let cipher = Aes256Gcm::new(&key.into());
    let mut decrypted_data = ciphertext.to_vec();
    cipher.decrypt_in_place(nonce, b"", &mut decrypted_data)
        .map_err(|e| format!("Decryption failed (invalid password?): {}", e))?;
    
    String::from_utf8(decrypted_data)
        .map_err(|e| format!("Invalid UTF-8 in decrypted private key: {}", e))
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

    let config_dir = get_config_dir()?;
    let config_file_path = config_dir.join(format!("{}.json", username));
    let existing_user = config_file_path.exists();
    let core_password = if existing_user {
        // 现有用户 - 只需验证密码
        read_password_from_stdin("Enter core password to authenticate: ")?
    } else {
        // 新用户 - 创建密码
        let password = read_password_from_stdin("Enter core password: ")?;
        let confirm = read_password_from_stdin("Confirm core password: ")?;
        if password != confirm {
            return Err("Passwords do not match".to_string());
        }
        password
    };

    // 评估新用户密码强度
    if !existing_user {
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
    } else {
        // 验证现有用户密码
        let existing_config = fs::read_to_string(&config_file_path)
            .map_err(|e| format!("Failed to read existing config: {}", e))?;
        let config: ConfigFile = serde_json::from_str(&existing_config)
            .map_err(|e| format!("Failed to parse config: {}", e))?;

        decrypt_private_key(&config.encrypted_private_key, &core_password)
            .map_err(|e| format!("Authentication failed: {}", e))?;
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

    let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let mut new_vault = Vault {
        name: vault_name.to_string(),
        path: vault_path.clone(),
        is_default: false,
        created_at: now.clone(),
        last_modified: now.clone(),
    };

    let config = if existing_user {
        // 加载现有配置
        let existing_config = fs::read_to_string(&config_file_path)
            .map_err(|e| format!("Failed to read existing config: {}", e))?;
        let mut config: ConfigFile = serde_json::from_str(&existing_config)
            .map_err(|e| format!("Failed to parse config: {}", e))?;

        // 列出当前所有密码库
        println!("\nExisting vaults:");
        for (i, vault) in config.vaults.iter().enumerate() {
            println!("{}. {} (Path: {}, Default: {})", 
                     i + 1, 
                     vault.name, 
                     vault.path, 
                     if vault.is_default { "Yes" } else { "No" });
        }
        println!("{}. {} (new vault)", config.vaults.len() + 1, new_vault.name);

        // 询问用户选择默认密码库
        print!("\nEnter the number of the vault to set as default: ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut response = String::new();
        io::stdin().read_line(&mut response).map_err(|e| e.to_string())?;
        let selection: usize = response.trim().parse()
            .map_err(|_| "Invalid selection. Please enter a number.".to_string())?;

        // 验证选择
        if selection < 1 || selection > config.vaults.len() + 1 {
            return Err(format!("Invalid selection. Please enter a number between 1 and {}", config.vaults.len() + 1));
        }

        // 重置所有默认标志
        for vault in &mut config.vaults {
            vault.is_default = false;
        }

        // 设置选中的默认密码库
        if selection <= config.vaults.len() {
            // 选择现有密码库
            config.vaults[selection - 1].is_default = true;
        } else {
            // 选择新密码库
            new_vault.is_default = true;
        }

        // 添加新密码库到配置
        config.vaults.push(new_vault);
        config
    } else {
        // 生成RSA密钥对
        println!("Generating RSA key pair...");
        let (private_key_pem, public_key_pem) = generate_rsa_keypair()?;

        // 加密私钥
        println!("Encrypting private key...");
        let encrypted_private_key = encrypt_private_key(&private_key_pem, &core_password)?;

        // 创建新配置
        new_vault.is_default = true;
        ConfigFile {
            username: username.to_string(),
            encrypted_private_key,
            public_key: public_key_pem,
            vaults: vec![new_vault],
        }
    };

    // 保存配置文件
    fs::create_dir_all(&config_dir)
        .map_err(|e| format!("Failed to create config directory: {}", e))?;
    let config_file = fs::File::create(&config_file_path)
        .map_err(|e| format!("Failed to create config file: {}", e))?;
    serde_json::to_writer_pretty(config_file, &config)
        .map_err(|e| format!("Failed to write config file: {}", e))?;

    // 创建密码库元数据
    let metadata = VaultMetadata {
        name: vault_name.to_string(),
        path: vault_path,
        created_at: now.clone(),
        last_modified: now.clone(),
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

    // 尝试解析为新格式
    let new_config: Result<ConfigFile, _> = serde_json::from_str(&config_data);
    let config = if let Ok(cfg) = new_config {
        cfg
    } else {
        // 尝试解析为旧格式并转换
        #[derive(Debug, Serialize, Deserialize)]
        struct OldConfigFile {
            username: String,
            encrypted_private_key: String,
            public_key: String,
            vault_name: String,
            vault_path: String,
            default_vault: bool,
        }

        let old_config: OldConfigFile = serde_json::from_str(&config_data)
            .map_err(|e| format!("Invalid config file format: {}", e))?;

        // 获取当前时间作为创建和修改时间
        let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        ConfigFile {
            username: old_config.username,
            encrypted_private_key: old_config.encrypted_private_key,
            public_key: old_config.public_key,
            vaults: vec![Vault {
                name: old_config.vault_name,
                path: old_config.vault_path,
                is_default: old_config.default_vault,
                created_at: now.clone(),
                last_modified: now,
            }],
        }
    };

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
    for vault in &config.vaults {
        let vault_path = PathBuf::from(&vault.path);
        fs::create_dir_all(&vault_path)
            .map_err(|e| format!("Failed to create vault directory: {}", e))?;
    }

    Ok(())
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();

    match cli {
        Cli::Init { import } => {
            if let Some(import_path) = import {
                import_config(&import_path)
            } else {
                interactive_init()
            }
        },
        Cli::Gen(args) => {
            let options = PasswordOptions::from(args);
            let password = generate_password(&options)?;
            println!("Generated password: {}", password);
            Ok(())
        },
        Cli::Add { user, vault } => {
            add_password_interactive(user, vault)
        },
        Cli::Update => {
            Ok(())
        },
        Cli::List => {
            Ok(())
        },
        Cli::Search => {
            Ok(())
        },
        Cli::Testpass(args) => {
            let (rating, score, feedback) = assess_password_strength(&args.password);
            println!("Password strength: {} (score: {}/4)", rating, score);
            if !feedback.is_empty() {
                println!("Suggestions: {}", feedback);
            }

            if args.check_url_safe {
                let is_safe = check_url_safe(&args.password);
                println!("URL-safe: {}", if is_safe { "Yes" } else { "No" });
            }

            if args.check_confusion {
                let confusing = check_confusing_chars(&args.password);
                if !confusing.is_empty() {
                    println!("Potentially confusing characters: {:?}", confusing);
                } else {
                    println!("No confusing characters detected");
                }
            }
            Ok(())
        }
    }
}

fn add_password_interactive(user_arg: Option<String>, vault_arg: Option<String>) -> Result<(), String> {
    // 获取配置目录
    let config_dir = get_config_dir()?;
    
    // 列出所有现有用户
    let user_files = fs::read_dir(&config_dir)
        .map_err(|e| format!("Failed to read config directory: {}", e))?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                path.file_stem()?.to_str().map(|s| s.to_string())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    
    // 处理用户选择
    let username = if let Some(user) = user_arg {
        user
    } else if user_files.is_empty() {
        return Err("No users found. Please initialize a user first with `rpawomaster init`".to_string());
    } else {
        println!("Available users:");
        for (i, user) in user_files.iter().enumerate() {
            println!("{}. {}", i + 1, user);
        }
        
        print!("Enter user number to select: ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut response = String::new();
        io::stdin().read_line(&mut response).map_err(|e| e.to_string())?;
        let selection: usize = response.trim().parse()
            .map_err(|_| "Invalid selection. Please enter a number.".to_string())?;
        
        if selection < 1 || selection > user_files.len() {
            return Err(format!("Invalid selection. Please enter a number between 1 and {}", user_files.len()));
        }
        
        user_files[selection - 1].clone()
    };
    
    // 读取用户配置
    let config_file_path = config_dir.join(format!("{}.json", username));
    let config_data = fs::read_to_string(&config_file_path)
        .map_err(|e| format!("Failed to read user config: {}", e))?;
    let config: ConfigFile = serde_json::from_str(&config_data)
        .map_err(|e| format!("Failed to parse user config: {}", e))?;
    
    // 验证核心密码
    let core_password = read_password_from_stdin(&format!("Enter core password for user '{}': ", username))?;
    let private_key_pem = decrypt_private_key(&config.encrypted_private_key, &core_password)?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_pem)
                                        .map_err(|e| format!("Failed to parse private key: {}", e))?;
    let public_key = private_key.to_public_key();
    
    // 确定密码库
    let vault_name = if let Some(vault) = vault_arg {
        vault
    } else {
        // 查找默认密码库
        config.vaults.iter()
            .find(|v| v.is_default)
            .map(|v| v.name.clone())
            .ok_or("No default vault found for user".to_string())?
    };
    
    // 查找密码库路径
    let vault = config.vaults.iter()
        .find(|v| v.name == vault_name)
        .ok_or(format!("Vault '{}' not found for user", vault_name))?;
    
    // 获取密码库数据库路径
    let db_path = PathBuf::from(&vault.path).join("passwords.db");
    let db_path_str = db_path.to_string_lossy().into_owned();
    
    // 初始化数据库（如果不存在）
    pwsmanager::init_database(&db_path_str).map_err(|e| e.to_string())?;
    
    // 创建密码命令处理器
    let handler = pwsmanager::PasswordCommandHandler::new(
        db_path_str.clone(),
        public_key
    );
    
    // 获取密码信息
    print!("Enter password name/identifier: ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut name = String::new();
    io::stdin().read_line(&mut name).map_err(|e| e.to_string())?;
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("Password name cannot be empty".to_string());
    }
    
    print!("Enter username for this password (optional): ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut username_field = String::new();
    io::stdin().read_line(&mut username_field).map_err(|e| e.to_string())?;
    let username_field = if username_field.trim().is_empty() { None } else { Some(username_field.trim().to_string()) };
    
    print!("Enter URL (optional): ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut url = String::new();
    io::stdin().read_line(&mut url).map_err(|e| e.to_string())?;
    let url = if url.trim().is_empty() { None } else { Some(url.trim().to_string()) };
    
    print!("Enter expiry days (0 for never, default: 90): ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut expiry_days_str = String::new();
    io::stdin().read_line(&mut expiry_days_str).map_err(|e| e.to_string())?;
    let expiry_days = if expiry_days_str.trim().is_empty() {
        90
    } else {
        expiry_days_str.trim().parse()
            .map_err(|_| "Invalid expiry days. Please enter a number.".to_string())?
    };
    
    print!("Enter note (optional): ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut note = String::new();
    io::stdin().read_line(&mut note).map_err(|e| e.to_string())?;
    let note = if note.trim().is_empty() { None } else { Some(note.trim().to_string()) };
    
    // 处理密码生成或输入
    print!("Do you want to generate a password or enter manually? [g/m] (default: g): ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut password_choice = String::new();
    io::stdin().read_line(&mut password_choice).map_err(|e| e.to_string())?;
    let password_choice = password_choice.trim().to_lowercase();
    
    let (manual_password, generation_policy) = if password_choice == "m" {
        let password = read_password_from_stdin("Enter password: ")?;
        let confirm = read_password_from_stdin("Confirm password: ")?;
        if password != confirm {
            return Err("Passwords do not match".to_string());
        }
        (Some(password), None)
    } else {
        // 获取密码生成策略
        let mut policy = pwsmanager::PasswordGenerationPolicy::default();
        
        print!("Include uppercase letters? [Y/n] (default: Y): ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut input = String::new();
        io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
        policy.include_uppercase = input.trim().to_lowercase() != "n";
        
        print!("Include lowercase letters? [Y/n] (default: Y): ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        input.clear();
        io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
        policy.include_lowercase = input.trim().to_lowercase() != "n";
        
        print!("Include numbers? [Y/n] (default: Y): ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        input.clear();
        io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
        policy.include_numbers = input.trim().to_lowercase() != "n";
        
        print!("Include special characters? [Y/n] (default: Y): ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        input.clear();
        io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
        policy.include_special_chars = input.trim().to_lowercase() != "n";
        
        print!("Make URL-safe? [y/N] (default: N): ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        input.clear();
        io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
        policy.url_safe = input.trim().to_lowercase() == "y";
        
        print!("Exclude confusing characters? [Y/n] (default: Y): ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        input.clear();
        io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
        policy.exclude_confusing_chars = input.trim().to_lowercase() != "n";
        
        print!("Enter password length (default: 16): ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        input.clear();
        io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
        if !input.trim().is_empty() {
            policy.length = input.trim().parse()
                .map_err(|_| "Invalid length. Please enter a number.".to_string())?;
        }
        
        let options = PasswordOptions {
            length: policy.length,
            include_uppercase: policy.include_uppercase,
            include_lowercase: policy.include_lowercase,
            include_numbers: policy.include_numbers,
            include_special: policy.include_special_chars,
            url_safe: policy.url_safe,
            avoid_confusion: policy.exclude_confusing_chars,
        };
        let password = generate_password(&options)?;
        (Some(password), Some(policy))
    };
    
    // 创建添加密码选项
    let options = pwsmanager::AddPasswordOptions {
        user: username.clone(),
        vault: Some(vault_name.clone()),
        name,
        username: username_field,
        url,
        expiry_days,
        note,
        manual_password,
        generation_policy,
    };
    
    // 添加密码
    let entry = match handler.add_password(options) {
        Ok(result) => result,
        Err(e) => return Err(format!("Failed to add password: {}", e)),
    };
    
    println!(
        "Successfully added password '{}' to vault '{}' for user '{}' (ID: {})",
        entry.name,
        vault_name,
        username,
        entry.id
    );
    
    Ok(())
}
