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

mod pwsmanager;
mod passgen;
mod securecrypto;

use clap::{Parser, Args};
use rand::rngs::OsRng;
use aes_gcm::{Aes256Gcm, AeadInPlace, KeyInit, Nonce};
use pbkdf2::pbkdf2;
use sha2::Sha256;
use hmac::Hmac;
use serde::{Serialize, Deserialize};
use serde_json;
use std::fs;
use sled::IVec;
use std::path::PathBuf;
use dirs::config_dir;
use rpassword::read_password;
use hex::encode;
use rand::RngCore;
use std::io::{self, Write};
use chrono::Local;

use crate::passgen::Capitalization;
use crate::securecrypto::SecureCrypto;
use crate::pwsmanager::PasswordManager;

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

    /// Generate a new password
    Gen {
        #[command(subcommand)]
        subcommand: GenSubcommand,
    },

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
    List {
        /// User to filter passwords by
        #[arg(short, long)]
        user: Option<String>,
        
        /// Vault to list passwords from
        #[arg(short, long)]
        vault: Option<String>,
    },

    /// Search passwords in the vault
    Search {
        /// Text to search for
        text: String,
        
        /// User to filter passwords by
        #[arg(short, long)]
        user: Option<String>,
        
        /// Vault to search in
        #[arg(short, long)]
        vault: Option<String>,
    },

    /// Test password strength and properties
    Testpass(TestpassArgs),

    /// List all password vaults
    Vaults {
        /// User to list vaults for
        #[arg(short, long)]
        user: Option<String>,
    },

    /// Encrypt or decrypt files/directories
    Crypt {
        #[command(subcommand)]
        subcommand: CryptSubcommand,
    },
}

#[derive(Debug, Parser)]
enum GenSubcommand {
    /// Generate a random password
    Random(GenRandomArgs),
    
    /// Generate a memorable password
    Memorable(GenMemorableArgs),
}

#[derive(Debug, Parser)]
enum CryptSubcommand {
    /// Encrypt a file or directory
    En {
        /// User to use for encryption
        #[arg(short, long)]
        user: Option<String>,
        
        /// Source path to encrypt
        #[arg(short, long)]
        source: String,
        
        /// Target path to save encrypted file
        #[arg(short, long)]
        target: String,
    },
    
    /// Decrypt a file or directory
    De {
        /// User to use for decryption
        #[arg(short, long)]
        user: Option<String>,
        
        /// Source path to decrypt
        #[arg(short, long)]
        source: String,
        
        /// Target path to save decrypted file
        #[arg(short, long)]
        target: String,
    },
}

#[derive(Debug, Parser)]
struct GenRandomArgs {
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

#[derive(Debug, Parser)]
struct GenMemorableArgs {
    /// Number of words in the password
    #[arg(short, long, default_value_t = 4)]
    words: usize,

    /// Separator character between words
    #[arg(short, long, default_value_t = '-')]
    separator: char,

    /// Include numbers in the password
    #[arg(short, long, default_value_t = false)]
    include_numbers: bool,

    /// Capitalization style (none, camel, random)
    #[arg(short, long, default_value_t = Capitalization::CamelCase)]
    capitalization: Capitalization,
}

#[derive(Debug, Args, Serialize, Deserialize)]
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

#[derive(Debug, Args, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
struct VaultMetadata {
    name: String,
    path: String,
    created_at: String,
    last_modified: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    
    // 检查数据长度
    if data.len() < 16 + 12 {
        return Err("Encrypted private key is too short - must contain at least salt (16 bytes) and nonce (12 bytes)".to_string());
    }
    
    // 提取盐、nonce和密文
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
        let (rating, score, feedback) = passgen::assess_password_strength(&core_password)?;
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
        Cli::Gen { subcommand } => match subcommand {
            GenSubcommand::Random(args) => {
                let options = passgen::PasswordOptions {
                    length: args.length,
                    include_uppercase: !args.no_uppercase,
                    include_lowercase: !args.no_lowercase,
                    include_numbers: !args.no_numbers,
                    include_special: !args.no_special,
                    url_safe: args.url_safe,
                    avoid_confusion: args.avoid_confusion,
                };
                let password = passgen::generate_password(&options)?;
                let (rating, score, feedback) = passgen::assess_password_strength(&password)?;
                println!("Generated random password: {}", password);
                println!("密码安全等级: {} (评分: {})", rating, score);
                if score < 2 {
                    eprintln!("⚠️ 警告: 密码安全等级较低 - {}", feedback);
                }
                Ok(())
            },
            GenSubcommand::Memorable(args) => {
                let options = passgen::MemorablePasswordOptions {
                    word_count: args.words,
                    separator: args.separator,
                    include_numbers: args.include_numbers,
                    capitalization: args.capitalization,
                };
                let password = passgen::generate_memorable_password(&options)?;
                let (rating, score, feedback) = passgen::assess_password_strength(&password)?;
                println!("Generated memorable password: {}", password);
                println!("密码安全等级: {} (评分: {})", rating, score);
                if score < 2 {
                    eprintln!("⚠️ 警告: 密码安全等级较低 - {}", feedback);
                }
                Ok(())
            }
        },
        Cli::Add { user, vault } => {
            add_password_interactive(user, vault)
        },
        Cli::Update => {
            Ok(())
        },
        Cli::List { user, vault } => {
            // 获取用户名
            let username = match user {
                Some(u) => u.to_string(),
                None => {
                    print!("Enter username: ");
                    io::stdout().flush().map_err(|e| e.to_string())?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
                    let input = input.trim();
                    if input.is_empty() {
                        return Err("Username cannot be empty".to_string());
                    }
                    input.to_string()
                }
            };

            // 加载用户配置
            let config_dir = get_config_dir()?;
            let config_file_path = config_dir.join(format!("{}.json", username));
            if !config_file_path.exists() {
                return Err(format!("No configuration found for user '{}'. Please initialize first.", username));
            }
            let config_data = fs::read_to_string(&config_file_path)
                .map_err(|e| format!("Failed to read config file: {}", e))?;
            let config: ConfigFile = serde_json::from_str(&config_data)
                .map_err(|e| format!("Failed to parse config file: {}", e))?;

            // 处理密码库选择
            let vault_path = match vault {
                Some(v) => {
                    // 尝试按名称查找密码库
                    if let Some(vault) = config.vaults.iter().find(|vault| vault.name == *v) {
                        vault.path.clone()
                    } else {
                        // 未找到对应名称的密码库
                        return Err(format!("Vault '{}' not found. Available vaults: {}", 
                            v, 
                            config.vaults.iter().map(|v| &v.name).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
                    }
                },
                None => {
                    if config.vaults.len() == 1 {
                        // 只有一个密码库，直接使用
                        config.vaults[0].path.clone()
                    } else {
                        // 查找默认密码库
                        if let Some(default_vault) = config.vaults.iter().find(|v| v.is_default) {
                            default_vault.path.clone()
                        } else {
                            // 让用户选择密码库
                            println!("Available vaults:");
                            for (i, v) in config.vaults.iter().enumerate() {
                                println!("{}. {} - {}", i+1, v.name, v.path);
                            }
                            print!("Enter vault number to use: ");
                            io::stdout().flush().map_err(|e| e.to_string())?;
                            let mut input = String::new();
                            io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
                            let selection: usize = input.trim().parse()
                                .map_err(|_| "Invalid selection. Please enter a number.".to_string())?;
                            if selection < 1 || selection > config.vaults.len() {
                                return Err(format!("Invalid selection. Please enter a number between 1 and {}", config.vaults.len()));
                            }
                            config.vaults[selection-1].path.clone()
                        }
                    }
                }
            };

            // 验证密码库路径存在
            let vault_path_buf = PathBuf::from(&vault_path);
            if !vault_path_buf.exists() {
                return Err(format!("Vault directory not found: {}", vault_path));
            }

            // 初始化密码管理器
            let manager = pwsmanager::PasswordManager::new(&vault_path)
                                            .map_err(|e| format!("Failed to initialize password manager: {}", e))?;
            // 获取所有密码条目
            let entries = manager.list_passwords()
                                        .map_err(|e| format!("Failed to list passwords: {}", e))?;

            // 打印表头
            println!("{:<10} | {:<10} | {:<40} | {:<30} | {:<5}", 
                     "名称", "用户名", "URL", "说明", "有效期");
            println!("{}", "-".repeat(105));

            // 打印每个条目的信息
            for entry in entries {
                let expires = entry.expires_at.map_or("永不过期".to_string(), |d| {
                    d.format("%Y-%m-%d").to_string()
                });
                println!("{:<10} | {:<10} | {:<40} | {:<30} | {:<5}",
                         entry.name,
                         entry.username.as_deref().unwrap_or("未设置"),
                         entry.url.as_deref().unwrap_or("无"),
                         entry.note.as_deref().unwrap_or("无"),
                         expires);
            }

            Ok(())
        },
        Cli::Search { text, user, vault } => {
            search_passwords(text, user, vault)
        },
        Cli::Testpass(args) => {
            let (rating, score, feedback) = passgen::assess_password_strength(&args.password)?;
            println!("Password strength: {} (score: {}/4)", rating, score);
            if !feedback.is_empty() {
                println!("Suggestions: {}", feedback);
            }

            if args.check_url_safe {
                let is_safe = passgen::check_url_safe(&args.password);
                println!("URL-safe: {}", if is_safe { "Yes" } else { "No" });
            }

            if args.check_confusion {
                let confusing = passgen::check_confusing_chars(&args.password);
                if !confusing.is_empty() {
                    println!("Potentially confusing characters: {:?}", confusing);
                } else {
                    println!("No confusing characters detected");
                }
            }
            Ok(())
        },
        Cli::Vaults { user } => {
            // Get username from argument or prompt
            let username = match user {
                Some(u) => u,
                None => {
                    print!("Enter username: ");
                    io::stdout().flush().map_err(|e| e.to_string())?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
                    input.trim().to_string()
                }
            };

            // Load user configuration
            let config_dir = get_config_dir()?;
            let config_file_path = config_dir.join(format!("{}.json", username));
            if !config_file_path.exists() {
                return Err(format!("No configuration found for user '{}'", username));
            }

            let config_data = fs::read_to_string(&config_file_path)
                .map_err(|e| format!("Failed to read config file: {}", e))?;
            let config: ConfigFile = serde_json::from_str(&config_data)
                .map_err(|e| format!("Failed to parse config file: {}", e))?;

            // Display vaults
            println!("\nPassword vaults for user '{}':", username);
            println!("{:<20} | {:<50} | {:<10}", "Name", "Path", "Default");
            println!("{}", "-".repeat(85));
            for vault in config.vaults {
                let default_mark = if vault.is_default { "✓" } else { "" };
                println!("{:<20} | {:<50} | {:<10}", vault.name, vault.path, default_mark);
            }
            Ok(())
        },
        Cli::Crypt { subcommand } => match subcommand {
            CryptSubcommand::En { user, source, target } => {
                // 获取用户名
                let username = match user {
                    Some(u) => u,
                    None => {
                        print!("Enter username: ");
                        io::stdout().flush().map_err(|e| e.to_string())?;
                        let mut input = String::new();
                        io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
                        input.trim().to_string()
                    }
                };

                // 获取core password
                let core_password = read_password_from_stdin("Enter core password: ")?;

                // 加载配置文件
                let config_dir = get_config_dir()?;
                let config_file_path = config_dir.join(format!("{}.json", username));
                let config_data = fs::read_to_string(&config_file_path)
                    .map_err(|e| format!("Failed to read config file: {}", e))?;
                let config: ConfigFile = serde_json::from_str(&config_data)
                    .map_err(|e| format!("Failed to parse config: {}", e))?;

                // 解密私钥
                let private_key = decrypt_private_key(&config.encrypted_private_key, &core_password)?;

                // 初始化SecureCrypto
                let secure_crypto = SecureCrypto::from_pem_keys(&config.public_key,&private_key)
                    .map_err(|e| format!("Failed to initialize crypto: {}", e))?;

                // 执行加密
                secure_crypto.encrypt_path(&source, &target)
                    .map_err(|e| format!("Encryption failed: {}", e))?;
                println!("Successfully encrypted '{}' to '{}'", source, target);
                Ok(())
            },
            CryptSubcommand::De { user, source, target } => {
                // 获取用户名
                let username = match user {
                    Some(u) => u,
                    None => {
                        print!("Enter username: ");
                        io::stdout().flush().map_err(|e| e.to_string())?;
                        let mut input = String::new();
                        io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
                        input.trim().to_string()
                    }
                };

                // 获取core password
                let core_password = read_password_from_stdin("Enter core password: ")?;

                // 加载配置文件
                let config_dir = get_config_dir()?;
                let config_file_path = config_dir.join(format!("{}.json", username));
                let config_data = fs::read_to_string(&config_file_path)
                    .map_err(|e| format!("Failed to read config file: {}", e))?;
                let config: ConfigFile = serde_json::from_str(&config_data)
                    .map_err(|e| format!("Failed to parse config: {}", e))?;

                // 解密私钥
                let private_key = decrypt_private_key(&config.encrypted_private_key, &core_password)?;

                // 初始化SecureCrypto
                let secure_crypto = SecureCrypto::from_pem_keys(&config.public_key,&private_key)
                    .map_err(|e| format!("Failed to initialize crypto: {}", e))?;

                // 执行解密
                secure_crypto.decrypt_path(&source, &target)
                    .map_err(|e| format!("Decryption failed: {}", e))?;
                println!("Successfully decrypted '{}' to '{}'", source, target);
                Ok(())
            }
        },
    }
}

fn add_password_interactive(user_arg: Option<String>, vault_arg: Option<String>) -> Result<(), String> {
    // Get core password
    let core_password = read_password_from_stdin("Enter core password: ")?;

    // Get username
    let user = match user_arg {
        Some(u) => u,
        None => prompt_input("Enter username: ")?,
    };

    // Get config
    let config = load_config(&user)?;
    let private_key = decrypt_private_key(&config.encrypted_private_key, &core_password)?;
    let crypto = securecrypto::SecureCrypto::from_pem_keys(&config.public_key, &private_key)
        .map_err(|e| format!("Failed to initialize crypto: {}", e))?;

    // Select vault
    let vault = select_vault(&config, vault_arg)?;
    let manager = pwsmanager::PasswordManager::new(&vault.path)
        .map_err(|e| format!("Failed to open vault: {}", e))?;

    // Get password details
    let name = prompt_input("Enter password name/label: ")?;
    let username = prompt_input("Enter username (optional): ");
    let url = prompt_input("Enter URL (optional): ");
    let note = prompt_input("Enter note (optional): ");

    // Generate or input password
    let (password, policy, expiration_days) = loop {
        let choice = prompt_input("Generate password (g) or enter manually (m)? [g/m]: ")?;
        match choice.trim().to_lowercase().as_str() {
            "g" | "generate" => {
                let password_type = prompt_input("Generate random (r) or memorable (m) password? [r/m]: ")?;
                match password_type.trim().to_lowercase().as_str() {
                    "r" | "random" => {
                        let length_input = prompt_input("Enter password length (default 16): ")?;
                        let length = if length_input.trim().is_empty() {
                            16
                        } else {
                            length_input.parse().map_err(|_| "Invalid length".to_string())?
                        };
                        let mut options = passgen::PasswordOptions::default();
                        let mut password = String::new();
                        // Display default policy and get user confirmation
                        println!("Random password policy:");
                        println!("- Length: {}", length);
                        println!("- Includes uppercase: Yes");
                        println!("- Includes lowercase: Yes");
                        println!("- Includes numbers: Yes");
                        println!("- Includes special characters: Yes");
                        println!("- URL safe: No");
                        println!("- Avoid confusion: No");
                        let confirm_policy = prompt_input("Use this policy? [y/n]: ")?;
                        if confirm_policy.trim().to_lowercase() != "y" {
                            eprintln!("Customizing password policy...");
                            // Get custom length
                            let length_input = prompt_input("Enter password length (8-64): ")?;
                            let length: usize = length_input.trim().parse().expect("Invalid number");
                            // Get character set preferences
                            let uppercase = prompt_input("Include uppercase letters? [y/n]: ")?.trim().to_lowercase() == "y";
                            let lowercase = prompt_input("Include lowercase letters? [y/n]: ")?.trim().to_lowercase() == "y";
                            let numbers = prompt_input("Include numbers? [y/n]: ")?.trim().to_lowercase() == "y";
                            let special = prompt_input("Include special characters? [y/n]: ")?.trim().to_lowercase() == "y";
                            let url_safe = prompt_input("Make URL safe? [y/n]: ")?.trim().to_lowercase() == "y";
                            let avoid_confusion = prompt_input("Avoid confusing characters? [y/n]: ")?.trim().to_lowercase() == "y";
                            // Generate password with custom policy
                            options = passgen::PasswordOptions {
                                length,
                                include_uppercase: uppercase,
                                include_lowercase: lowercase,
                                include_numbers: numbers,
                                include_special: special,
                                url_safe,
                                avoid_confusion,
                            };
                            password = passgen::generate_password(&options)?;
                            println!("Generated password: {}", password);
                        } else {
                            let password = passgen::generate_password(&options)?;
                            println!("Generated password: {}", password);
                        }
                        
                        let confirm = prompt_input("Use this password? [y/n]: ")?;
                        if confirm.trim().to_lowercase() == "y" {
                            let policy = pwsmanager::PasswordPolicy::Random {
                                length: options.length,
                                include_uppercase: options.include_uppercase,
                                include_lowercase: options.include_lowercase,
                                include_numbers: options.include_numbers,
                                include_special: options.include_special,
                                url_safe: options.url_safe,
                                avoid_confusion: options.avoid_confusion,
                            };
                            let expiration_days_input = prompt_input("Enter password expiration days (0 for no expiration, default 0): ")?;
                            let expiration_days = if expiration_days_input.trim().is_empty() {
                                0
                            } else {
                                expiration_days_input.parse().map_err(|_| "Invalid expiration days".to_string())?
                            };
                            break (password, Some(policy), expiration_days);
                        }
                        continue;
                    },
                    "m" | "memorable" => {
                        let words_input = prompt_input("Enter number of words (default 4): ")?;
                        let words = if words_input.trim().is_empty() {
                            4
                        } else {
                            words_input.parse().map_err(|_| "Invalid number of words".to_string())?
                        };
                        let mut options = passgen::MemorablePasswordOptions::default();
                        let mut password = String::new();
                        // Display memorable password policy and get confirmation
                        println!("Memorable password policy:");
                        println!("- Number of words: {}", words);
                        println!("- Separator: '-'");
                        println!("- Include numbers: Yes");
                        println!("- Capitalization: CamelCase (first letter uppercase)");
                        let confirm_policy = prompt_input("Use this policy? [y/n]: ")?;
                        if confirm_policy.trim().to_lowercase() != "y" {
                            eprintln!("Customizing memorable password policy...");
                            // Get custom word count
                            let words_input = prompt_input("Enter number of words (3-10): ")?;
                            let words: usize = words_input.trim().parse().expect("Invalid number");
                            // Get separator
                            let separator = prompt_input("Enter separator character: ")?;
                            let separator = separator.trim().chars().next().unwrap_or('-');
                            // Get other preferences
                            let include_numbers = prompt_input("Include numbers? [y/n]: ")?.trim().to_lowercase() == "y";
                            // Get capitalization preference
                            let capitalization_input = prompt_input("Capitalization style (none/camel/random): ")?;
                            let capitalization = match capitalization_input.trim().to_lowercase().as_str() {
                                "camel" => passgen::Capitalization::CamelCase,
                                "random" => passgen::Capitalization::RandomCase,
                                _ => passgen::Capitalization::NoCapitalization,
                            };
                            // Generate password with custom policy
                            options = passgen::MemorablePasswordOptions {
                                word_count: words,
                                include_numbers,
                                separator,
                                capitalization,
                            };
                            password = passgen::generate_memorable_password(&options)?;
                            println!("Generated password: {}", password);
                        }

                        let confirm = prompt_input("Use this password? [y/n]: ")?;
                        if confirm.trim().to_lowercase() == "y" {
                            let policy = pwsmanager::PasswordPolicy::Memorable {
                                words: options.word_count as u8,
                                separator: options.separator,
                                include_numbers: options.include_numbers,
                                capitalization: options.capitalization,
                            };
                            let expiration_days_input = prompt_input("Enter password expiration days (0 for no expiration, default 0): ")?;
                            let expiration_days = if expiration_days_input.trim().is_empty() {
                                0
                            } else {
                                expiration_days_input.parse().map_err(|_| "Invalid expiration days".to_string())?
                            };
                            break (password, Some(policy), expiration_days);
                        }
                        continue;
                    },
                    _ => {
                        eprintln!("Invalid choice");
                        continue;
                    }
                };
            },
            "m" | "manual" => {
                let password = read_password_from_stdin("Enter password: ")?;
                let confirm = read_password_from_stdin("Confirm password: ")?;
                if password == confirm {
                    let expiration_days_input = prompt_input("Enter password expiration days (0 for no expiration, default 0): ")?;
                            let expiration_days = if expiration_days_input.trim().is_empty() {
                                0
                            } else {
                                expiration_days_input.parse().map_err(|_| "Invalid expiration days".to_string())?
                            };
                            break (password, None, expiration_days);
                } else {
                    eprintln!("Passwords do not match");
                    continue;
                }
            },
            _ => {
                eprintln!("Invalid choice");
                continue;
            }
        }
    };

    // Encrypt password using securecrypto
    let encrypted_bytes = crypto.encrypt_string(&password).expect("Encryption failed");

    // Add to vault
    let id = manager.add_password(
        name,
        username.ok(),
        encrypted_bytes,
        url.ok(),
        expiration_days, // Never expires
        policy,
        note.ok(),
    ).map_err(|e| format!("Failed to add password: {}", e))?;

    println!("Password added with ID: {}", id);
    Ok(())
}

fn load_config(username: &str) -> Result<ConfigFile, String> {
    // Get config directory
    let config_dir = get_config_dir()?;
    let config_file_path = config_dir.join(format!("{}.json", username));

    if !config_file_path.exists() {
        return Err(format!("Configuration file for user '{}' not found. Please run 'init' first.", username));
    }

    let config_data = fs::read_to_string(&config_file_path)
        .map_err(|e| format!("Failed to read config file: {}", e))?;

    serde_json::from_str(&config_data)
        .map_err(|e| format!("Failed to parse config file: {}", e))
}

fn select_vault(config: &ConfigFile, vault_arg: Option<String>) -> Result<Vault, String> {
    match vault_arg {
        Some(vault_name) => {
            let existing_vaults: Vec<_> = config.vaults.iter().map(|v| &v.name).collect();
            config.vaults.iter()
                .find(|v| v.name == vault_name)
                .cloned()
                .ok_or(format!("Vault '{}' not found. Existing vaults: {:?}", vault_name, existing_vaults))
        },
        None => {
            // Find default vault
            config.vaults.iter()
                .find(|v| v.is_default)
                .cloned()
                .ok_or("No default vault found. Please specify a vault or set a default.".to_string())
        }
    }
}

fn prompt_input(prompt: &str) -> Result<String, String> {
    print!("{}", prompt);
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    Ok(input.trim().to_string())
}

fn search_passwords(text: String, user: Option<String>, vault: Option<String>) -> Result<(), String> {
    // 获取用户名
    let username = match user {
        Some(u) => u,
        None => {
            print!("Enter username: ");
            io::stdout().flush().map_err(|e| e.to_string())?;
            let mut input = String::new();
            io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
            input.trim().to_string()
        }
    };

    // 获取配置文件路径
    let config_dir = get_config_dir()?;
    let config_file_path = config_dir.join(format!("{}.json", username));
    if !config_file_path.exists() {
        return Err(format!("User '{}' not found", username));
    }

    // 读取配置文件
    let config_data = fs::read_to_string(&config_file_path)
        .map_err(|e| format!("Failed to read config file: {}", e))?;
    let config: ConfigFile = serde_json::from_str(&config_data)
        .map_err(|e| format!("Failed to parse config file: {}", e))?;

    // 选择密码库
    let target_vault = match vault {
        Some(vault_name) => {
            config.vaults.iter()
                .find(|v| v.name == vault_name)
                .ok_or(format!("Vault '{}' not found", vault_name))?
        }
        None => {
            config.vaults.iter()
                .find(|v| v.is_default)
                .ok_or("No default vault found. Please specify a vault with --vault")?
        }
    };

    // 输入核心密码
    let core_password = read_password_from_stdin("Enter core password: ")?;

    // 解密私钥
    let private_key_pem = decrypt_private_key(&config.encrypted_private_key, &core_password)?;

    // 初始化SecureCrypto
    let crypto = SecureCrypto::from_pem_keys(&config.public_key, &private_key_pem)
        .map_err(|e| format!("Failed to initialize crypto: {}", e))?;

    // 初始化PasswordManager
    let pm = PasswordManager::new(&target_vault.path)
        .map_err(|e| format!("Failed to open vault: {}", e))?;

    // 搜索密码
    let entries = pm.find_passwords(&text, false)
        .map_err(|e| format!("Search failed: {}", e))?;

    if entries.is_empty() {
        println!("No passwords found matching '{}'", text);
        return Ok(());
    }

    // 显示搜索结果供选择
    println!("\nFound {} matching passwords:", entries.len());
    for (i, entry) in entries.iter().enumerate() {
        println!("{}. Name: {}", i + 1, entry.name);
        if let Some(username) = &entry.username {
            println!("   Username: {}", username);
        }
        if let Some(url) = &entry.url {
            println!("   URL: {}", url);
        }
        if let Some(note) = &entry.note {
            println!("   Note: {}", note);
        }
        println!();
    }

    // 让用户选择条目
    print!("Enter the number of the password to view: ");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut response = String::new();
    io::stdin().read_line(&mut response).map_err(|e| e.to_string())?;
    let selection: usize = response.trim().parse()
        .map_err(|_| "Invalid selection. Please enter a number.".to_string())?;

    if selection < 1 || selection > entries.len() {
        return Err(format!("Invalid selection. Please enter a number between 1 and {}", entries.len()));
    }

    let selected_entry = &entries[selection - 1];

    // 解密密码 - 支持新旧格式兼容
    let encrypted_bytes = selected_entry.current_password.clone();
    let decrypted_password = crypto.decrypt_string(&IVec::from(encrypted_bytes.clone()))
                                            .expect("Decryption failed");

    // 显示详细信息
    println!("\n--- Password Details ---");
    println!("Name: {}", selected_entry.name);
    if let Some(username) = &selected_entry.username {
        println!("Username: {}", username);
    }
    if let Some(url) = &selected_entry.url {
        println!("URL: {}", url);
    }
    println!("Password: {}", decrypted_password.clone());
    println!("------------------------");

    Ok(())
}
