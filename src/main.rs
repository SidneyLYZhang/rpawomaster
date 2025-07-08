//  ____  ____     __        __    __  __           _
// |  _ \|  _ \ __ \ \      / /__ |  \/  | __ _ ___| |_ ___ _ __ 
// | |_) | |_) / _` \ \ /\ / / _ \| |\/| |/ _` / __| __/ _ \ '__|
// |  _ <|  __/ (_| |\ V  V / (_) | |  | | (_| \__ \ ||  __/ |   
// |_| \_\_|   \__,_| \_/\_/ \___/|_|  |_|\__,_|___/\__\___|_|   
//
// Author : Sidney Zhang <zly@lyzhang.me>
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
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use aes_gcm::{Aes256Gcm, AeadInPlace, KeyInit, Nonce};
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
mod securecrypto;
mod passgen;

include!(concat!(env!("OUT_DIR"), "/word_data.rs"));

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

fn read_password_from_stdin(prompt: &str) -> Result<String, String> {
    print!("{}", prompt);
    io::stdout().flush().map_err(|e| format!("Failed to flush output: {}", e))?;
    read_password().map_err(|e| format!("Failed to read password: {}", e))
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
        let (private_key_pem, public_key_pem) = securecrypto::generate_rsa_keypair()?;

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
    Ok(())
}
