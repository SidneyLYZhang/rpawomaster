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
mod configtool;

use clap::{Parser, Args};
use serde::{Serialize, Deserialize};
use std::fs;
use sled::IVec;
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use std::io::{self, Write};

use crate::passgen::{
    Capitalization, 
    evaluate_and_display_password_strength, 
    generate_from_policy};
use crate::securecrypto::SecureCrypto;
use crate::pwsmanager::PasswordManager;
use crate::configtool::*;

#[derive(Debug, Parser)]
#[command(name = "rpawomaster")]
#[command(author, version, about = "A secure password manager written in Rust", long_about = None)]

enum Cli {
    /// Initialize a new password vault
    Init {
        /// Core Username
        #[arg(short, long)]
        user: Option<String>,

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
    Update {
        // Update all entries
        #[arg(short, long)]
        all: Option<bool>,

        /// Password name to update
        #[arg(short, long)]
        passwordname: Option<String>,

        /// User to update password for
        #[arg(short, long)]
        user: Option<String>,

        /// Vault to update password in 
        #[arg(short, long)]
        vault: Option<String>,
    },

    /// Delete an existing password
    Delete {
        /// Password name to delete
        passwordname: String,

        /// User to delete password from
        #[arg(short, long)]
        user: Option<String>,
        
        /// Vault to delete password from
        #[arg(short, long)]
        vault: Option<String>,
    },

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

        /// Search for exact match
        #[arg(short, long)]
        exact: Option<bool>,
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

    /// Export password vault
    Export {
        /// Export user data
        user: String,
        
        /// Path to export file
        #[arg(short, long)]
        path: Option<String>,

        /// Vault to export
        #[arg(short, long)]
        vault: Option<String>,
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

fn interactive_init(user: Option<String>) -> Result<(), String> {
    // 获取用户
    let username = match user {
        Some(u) => u,
        None => loop {
                let user_name = prompt_input("Enter username: ")?;
                if user_name.is_empty() {
                    println!("Username cannot be empty. Please try again.");
                    continue;
                }
                break user_name;
        },
    };

    let existing_user = check_user_exist(&username)?;
    let core_password = if existing_user {
        // 现有用户 - 只需验证密码
        let password = read_password_from_stdin("Enter core password to authenticate: ")?;
        let mut config: ConfigFile = load_config(&username, &password)?;
        config.check_corepassword_valid(&password)?;
        decrypt_private_key(&config.encrypted_private_key, &password)
            .map_err(|e| format!("Authentication failed: {}", e))?;
        password
    } else {
        // 新用户 - 创建密码
        let mut password;
        loop {
            password = read_password_from_stdin("Enter core password: ")?;
            let confirm = read_password_from_stdin("Confirm core password: ")?;
            if password != confirm {
                println!("Passwords do not match. Please try again.");
                continue;
            }
            // 评估密码强度
            let (rating, score, feedback) = passgen::assess_password_strength(&password)?;
            if score < 3 {
                println!("Warning: Weak core password. {}", feedback);
                println!("New Core Password is {} ({}/4).", rating, score);
                let response = prompt_input("Continue with this weak password? [y/N]: ")?;
                if !response.trim().eq_ignore_ascii_case("y") {
                    break;
                } else {
                    continue;
                }
            } else {
                println!("⭐ 核心密码强度 {} ({}/4).\n", rating, score);
            }
            break;
        }
        password
    };

    // 新建密码库
    let vault_name = prompt_input("Enter vault name (default: MyVault): ")?;
    let vault_name = if vault_name.is_empty() { "MyVault".to_string() } else { vault_name };

    let vault_path = prompt_input(
        format!("Enter vault save location (default: {{config path}}/vaults/{}): ", vault_name.clone()).as_str())?;
    let default_vault_path = get_config_dir()?
        .join("vaults")
        .join(vault_name.clone());
    let vault_path = if vault_path.is_empty() {
        default_vault_path.to_string_lossy().into_owned()
    } else {
        vault_path.to_string()
    };

    // 创建密码库目录
    let vault_path_buf = PathBuf::from(&vault_path);
    fs::create_dir_all(&vault_path_buf)
        .map_err(|e| format!("Failed to create vault directory: {}", e))?;
    
    // 新建密码库信息
    let mut new_vault = Vault::new(&vault_name, &vault_path, Some(false));
    // 加载配置文件
    let mut config = load_config(&username, &core_password)?;

    if existing_user {
        // 检查核心密码是否过期
        config.check_corepassword_valid(&core_password)?;
        // 列出当前所有密码库
        let mut default_vault_number = 0;
        println!("\nExisting vaults:");
        for (i, vault) in config.vaults.iter().enumerate() {
            if vault.is_default {
                default_vault_number = i + 1;
            }
            println!("{}. {} (Path: {}, Default: {})", 
                     i + 1, 
                     vault.name, 
                     vault.path, 
                     if vault.is_default { "Yes" } else { "No" });
        }
        println!("{}. {} (new vault)", config.vaults.len() + 1, new_vault.name);

        // 询问用户选择默认密码库
        let selection: usize = loop {
            let response = prompt_input("\nEnter the number of the vault to set as default: ")?;
            let selection: usize = if response.is_empty() {
                default_vault_number
            } else {
                response.parse()
                        .map_err(|_| "Invalid selection. Please enter a number.".to_string())?
            };
            if selection < 1 || selection > config.vaults.len() + 1 {
                println!("Invalid selection. Please enter a number between 1 and {}.", config.vaults.len() + 1);
                continue;
            }
            break selection;
        };

        if selection != default_vault_number {
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
        }
        // 添加新密码库到配置
        config.add_vault(new_vault.clone());
    } else {
        // 新用户 - 创建默认密码库
        new_vault.set_default(true);
        config.add_vault(new_vault.clone());
    }

    // 保存配置文件
    let _ = config.save_config();

    // 创建密码库元数据
    let metadata = VaultMetadata::from_vault(&new_vault);
    let _ = metadata.save_vaultmetadata();

    Ok(())
}

/// 选择密码库
fn select_vault_path(config: &ConfigFile, vault: Option<String>) -> Result<String, String> {
    match vault {
        Some(v) => {
            // 尝试按名称查找密码库
            if let Some(vault) = config.vaults.iter().find(|vault| vault.name == v) {
                Ok(vault.path.clone())
            } else {
                // 未找到对应名称的密码库
                Err(format!("Vault '{}' not found. Available vaults: {}", 
                    v, 
                    config.vaults.iter().map(|v| &v.name).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")))
            }
        },
        None => {
            if config.vaults.len() == 1 {
                // 只有一个密码库，直接使用
                Ok(config.vaults[0].path.clone())
            } else {
                // 查找默认密码库
                if let Some(default_vault) = config.vaults.iter().find(|v| v.is_default) {
                    Ok(default_vault.path.clone())
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
                    Ok(config.vaults[selection-1].path.clone())
                }
            }
        }
    }
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();

    match cli {
        Cli::Init { user, import } => {
            if let Some(import_path) = import {
                let mut vault_path = prompt_input("Enter vault path (default: config path): ")?;
                if vault_path.is_empty() {
                    vault_path = get_config_dir()?.to_string_lossy().to_string();
                }
                import_passvaults(import_path, vault_path).map_err(|e| e.to_string())
            } else {
                interactive_init(user)
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
                let password = passgen::generate_password(&options)
                    .map_err(|e| format!("Failed to generate password: {}", e))?;
                println!("Generated random password: {}", password);
                evaluate_and_display_password_strength(&password)?;
                Ok(())
            },
            GenSubcommand::Memorable(args) => {
                let options = passgen::MemorablePasswordOptions {
                    word_count: args.words,
                    separator: args.separator,
                    include_numbers: args.include_numbers,
                    capitalization: args.capitalization,
                };
                let password = passgen::generate_memorable_password(&options)
                    .map_err(|e| format!("Failed to generate memorable password: {}", e))?;
                println!("Generated memorable password: {}", password);
                evaluate_and_display_password_strength(&password)?;
                Ok(())
            }
        },
        Cli::Add { user, vault } => {
            add_password_interactive(user, vault)
        },
        Cli::Update { all, passwordname, user, vault } => {
            let need_all = all.unwrap_or(false);
            // 获取用户名
            let username = get_username(user)?;
            // 输入并确认核心密码
            let core_password = prompt_core_password(username.clone())?;
            // 加载配置
            let mut config = load_user_config(&username)?;
            // 选定密码库
            let mut vault = select_vault(&config, vault)?;
            // 加载私钥
            let private_key = decrypt_private_key(&config.encrypted_private_key, &core_password)?;
            // 创建加密对象
            let crypto = SecureCrypto::from_pem_keys(&config.public_key, &private_key)
                                                    .map_err(|e| format!("Failed to create crypto object: {}", e))?;
            // 加载密码库
            let pm = pwsmanager::PasswordManager::new(&vault.path)
                                            .map_err(|e| format!("Failed to initialize password manager: {}", e))?;
            // 更新密码
            if need_all {
                // 更新所有过期密码
                let entries = pm.get_password(None, Some(true))
                                    .map_err(|e| format!("Failed to get password: {}", e))?;
                for entry in entries.clone() {
                    let new_password = match entry.policy.clone() {
                        Some(policy) => generate_from_policy(&policy)?,
                        None => {
                            println!("Password {} has no policy. Please input new password.", entry.name);
                            input_password_check()?
                        },
                    };
                    let encrypted_password = crypto.encrypt_string(&new_password)
                                                            .map_err(|e| format!("Failed to encrypt password: {}", e))?;
                    pm.update_password(entry.id, encrypted_password)
                        .map_err(|e| format!("Failed to update password: {}", e))?;
                }
                println!("All expired passwords ({} in total) updated successfully.", entries.len());
            } else {
                // 确认需要更新的密码
                let pwname = match passwordname {
                    Some(name) => name,
                    None => prompt_input("Enter password name to update: ")?,
                };
                // 获取密码ID
                let id = pm.get_uuid(pwname.as_ref())
                                    .map_err(|e| format!("Failed to find password {}: {}", pwname, e))?;
                // 获取密码数据
                let entry = pm.get_password(Some(id), Some(false))
                                    .map_err(|e| format!("Failed to get password {}: {}", pwname, e))?;
                let new_password = match entry[0].policy.clone() {
                    Some(policy) => generate_from_policy(&policy)?,
                    None => input_password_check()?,
                };
                let encrypted_password = crypto.encrypt_string(&new_password)
                                                        .map_err(|e| format!("Failed to encrypt password: {}", e))?;
                pm.update_password(id, encrypted_password)
                    .map_err(|e| format!("Failed to update password: {}", e))?;
                println!("Password {} updated successfully.", pwname);
            }
            vault.update_vault();
            config.update_vault(vault);
            Ok(())
        },
        Cli::Delete { passwordname, user, vault } => {
            // 获取用户名
            let username = get_username(user)?;

            // 输入核心密码
            let _ = prompt_core_password(username.clone())?;

            // 加载用户配置
            let mut config = load_user_config(&username)?;

            // 处理密码库选择
            let mut vault = select_vault(&config, vault)?;

            let pm = pwsmanager::PasswordManager::new(&vault.path)
                                            .map_err(|e| format!("Failed to initialize password manager: {}", e))?;
            pm.delete_password(None, Some(passwordname.clone()))
                .map_err(|e| format!("Failed to delete password: {}", e))?;
            
            vault.update_vault();
            config.update_vault(vault);
            println!("Password {} deleted successfully.", passwordname);
            Ok(())
        },
        Cli::List { user, vault } => {
            // 获取用户名
            let username = get_username(user)?;

            // 加载用户配置
            let config = load_user_config(&username)?;

            // 处理密码库选择
            let vault_path = select_vault_path(&config, vault)?;

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
        Cli::Search { text, user, vault, exact } => {
            search_passwords(text, user, vault, exact)
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
            let username = get_username(user)?;

            // Load user configuration
            let config = load_user_config(&username)?;

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
                let username = get_username(user)?;

                // 获取core password
                let core_password = prompt_core_password(username.clone())?;

                // 正式加载配置文件
                let config = load_user_config(&username)?;

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
                let username = get_username(user)?;

                // 获取core password
                let core_password = prompt_core_password(username.clone())?;

                // 正式加载配置文件
                let config: ConfigFile = load_config(&username, &core_password)?;

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
        Cli::Export { user, path , vault } => {
            // 处理导出路径，默认为当前目录
            let output_dir = match path {
                Some(p) => p,
                None => std::env::current_dir()
                    .map(|dir| dir.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| ".".to_string()),
            };

            // 确认核心密码
            let core_password = prompt_core_password(user.clone())?;

            // 获取用户名
            let username = get_username(Some(user.clone()))?.clone();

            // 获取用户配置
            let config = load_config(&username, &core_password)?;
            let vaults = config.vaults.clone();
            let select_vaults = if vault.is_some() {
                let vault_name = vault.unwrap();
                let vault = vaults.iter().find(|v| v.name == vault_name)
                                            .ok_or_else(|| format!("未找到指定的Vault: {}", vault_name))?;
                vec![vault.clone()]
            } else {
                vaults
            };
            
            // 解密私钥
            let private_key = decrypt_private_key(&config.encrypted_private_key, &core_password)?;
            // 创建加密器
            let crypto = SecureCrypto::from_pem_keys(&config.public_key, &private_key)
                .map_err(|e| format!("Failed to initialize crypto: {}", e))?;

            // 确保导出目录存在
            let export_dir = Path::new(&output_dir);
            if !export_dir.exists() {
                fs::create_dir_all(&export_dir)
                    .map_err(|e| format!("创建导出目录失败: {}", e))?;
            }

            // 构建导出文件名
            let export_filename = format!("{}.tgz", user);
            let export_path = export_dir.join(export_filename);

            // 创建临时文件夹，拷贝Vault文件
            let temp_dir = tempdir().map_err(|e| format!("创建临时文件夹失败: {}", e))?;
            let temp_path = temp_dir.path();
            for vault in &select_vaults {
                let src_path = Path::new(&vault.path);
                crypto.encrypt_path(src_path, temp_path)
                        .map_err(|e| format!("加密Vault文件失败: {}", e))?;
            }
            // 拷贝用户配置文件
            let config_file_path = get_config_dir()?.join(format!("{}.json", user));
            let dest_config_path = temp_path.join(format!("{}.json", user));
            fs::copy(config_file_path, dest_config_path).map_err(|e| format!("复制配置文件失败: {}", e))?;

            // 执行导出和打包
            crypto.create_tar_archive(
                temp_path,
                &export_path,
            ).map_err(|e| format!("创建加密归档失败: {}", e))?;

            println!("成功导出用户 '{}' 的数据到: {}", user, export_path.display());
            Ok(())
        },
    }
}

fn add_password_interactive(user_arg: Option<String>, vault_arg: Option<String>) -> Result<(), String> {
    // Get username
    let user = get_username(user_arg)?;
    // Get core password
    let core_password = prompt_core_password(user.clone())?;

    // Get config
    let config = load_config(&user, &core_password)?;
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
                        options = if confirm_policy.trim().to_lowercase() != "y" {
                            eprintln!("Customizing password policy...");
                            // Get character set preferences
                            let uppercase = prompt_input("Include uppercase letters? [y/n]: ")?.trim().to_lowercase() == "y";
                            let lowercase = prompt_input("Include lowercase letters? [y/n]: ")?.trim().to_lowercase() == "y";
                            let numbers = prompt_input("Include numbers? [y/n]: ")?.trim().to_lowercase() == "y";
                            let special = prompt_input("Include special characters? [y/n]: ")?.trim().to_lowercase() == "y";
                            let url_safe = prompt_input("Make URL safe? [y/n]: ")?.trim().to_lowercase() == "y";
                            let avoid_confusion = prompt_input("Avoid confusing characters? [y/n]: ")?.trim().to_lowercase() == "y";
                            // Generate password with custom policy
                            passgen::PasswordOptions {
                                length,
                                include_uppercase: uppercase,
                                include_lowercase: lowercase,
                                include_numbers: numbers,
                                include_special: special,
                                url_safe,
                                avoid_confusion,
                            }
                        } else {
                            passgen::PasswordOptions {
                                length,
                                ..options
                            }
                        };
                        let password = passgen::generate_password(&options)?;
                        println!("Generated password: {}", password);
                        
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
                        // Display memorable password policy and get confirmation
                        println!("Memorable password policy:");
                        println!("- Number of words: {}", words);
                        println!("- Separator: '-'");
                        println!("- Include numbers: Yes");
                        println!("- Capitalization: CamelCase (first letter uppercase)");
                        let confirm_policy = prompt_input("Use this policy? [y/n]: ")?;
                        options = if confirm_policy.trim().to_lowercase() != "y" {
                            eprintln!("Customizing memorable password policy...");
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
                            passgen::MemorablePasswordOptions {
                                word_count: words,
                                include_numbers,
                                separator,
                                capitalization,
                            }
                        } else {
                            passgen::MemorablePasswordOptions {
                                word_count: words,
                                ..options
                            }
                        };
                        let password = passgen::generate_memorable_password(&options)?;
                        println!("Generated password: {}", password);

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
                let password = input_password_check()?;
                let expiration_days_input = prompt_input("Enter password expiration days (0 for no expiration, default 0): ")?;
                let expiration_days = if expiration_days_input.trim().is_empty() {
                    0
                } else {
                    expiration_days_input.parse().map_err(|_| "Invalid expiration days".to_string())?
                };
                break (password, None, expiration_days);
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

    {
        let mut vault_meta = VaultMetadata::get_vaultmetadata(&vault.path).unwrap();
        vault_meta.vault_updated();
    }

    println!("Password added with ID: {}", id);
    Ok(())
}

fn import_passvaults(filepath: String, vaultspath: String) -> Result<(), Box<(dyn std::error::Error + 'static)>> {
    // 创建中间解压目录
    let temp_dir = tempdir().map_err(|e| format!("Failed to create temp directory: {}", e))?;
    let temp_path = temp_dir.path();

    // 解压初始包
    let file_path = Path::new(&filepath);
    {
        let crypto = SecureCrypto::new().map_err(|e| format!("Failed to create crypto: {}", e))?;
        crypto.extract_tar_archive(file_path, temp_path)?;
    }

    // 导入用户配置文件
    let username = file_path.file_stem().map(|s| s.to_string_lossy().to_string()).ok_or("Failed to get username from filepath")?;
    let config_path = get_config_dir()?;
    let config_file_path = config_path.join(format!("{}.json", &username));
    fs::copy(temp_path.join(format!("{}.json", &username)), config_file_path)?;

    // 输入核心密码，并验证
    let password = prompt_core_password(username.clone())?;

    //加载用户配置
    let config = load_config(&username, &password)?;
    // 解密私钥
    let private_key = decrypt_private_key(&config.encrypted_private_key, &password)?;
    // 加载加密器
    let crypto = SecureCrypto::from_pem_keys(&config.public_key, &private_key)?;
    // 解密密码库
    let vault_names = config.vaults.iter().map(|v| &v.name).collect::<Vec<_>>();
    for vault in vault_names {
        let encrypted_vault_path = temp_path.join(format!("{}.tgz.esz",vault));
        crypto.decrypt_path(encrypted_vault_path, vaultspath.clone())?;
    }
    Ok(())
}

fn search_passwords(text: String, user: Option<String>, vault: Option<String>, exact: Option<bool>) -> Result<(), String> {
    // 获取用户名
    let username = get_username(user)?;

    // 输入核心密码
    let core_password = prompt_core_password(username.clone())?;

    // 获取配置信息
    let config: ConfigFile = load_config(&username, &core_password)?;

    // 选择密码库
    let target_vault = select_vault(&config, vault)?;

    // 解密私钥
    let private_key_pem = decrypt_private_key(&config.encrypted_private_key, &core_password)?;

    // 初始化SecureCrypto
    let crypto = SecureCrypto::from_pem_keys(&config.public_key, &private_key_pem)
        .map_err(|e| format!("Failed to initialize crypto: {}", e))?;
    
    // 搜索是否为精确匹配
    let exact_match = exact.unwrap_or(false);

    // 初始化PasswordManager
    let pm = PasswordManager::new(&target_vault.path)
        .map_err(|e| format!("Failed to open vault: {}", e))?;

    // 搜索密码
    let entries = pm.find_passwords(&text, exact_match)
        .map_err(|e| format!("Search failed: {}", e))?;

    if entries.is_empty() {
        println!("No passwords found matching '{}'", text);
        return Ok(());
    }

    // 显示搜索结果供选择
    let entry_count = entries.len();
    let selected_entry = if entry_count > 1 {
        println!("\nFound {} matching passwords:", entry_count.clone());
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
        let selection = prompt_input("Enter the number of the password to view: ")?;
        let selection: usize = selection.trim().parse()
            .map_err(|_| "Invalid selection. Please enter a number.".to_string())?;
        if selection < 1 || selection > entry_count {
            return Err(format!("Invalid selection. Please enter a number between 1 and {}", entry_count));
        }
        &entries[selection - 1]
    } else {
        &entries[0]
    };

    // 解密密码 - 支持新旧格式兼容
    let encrypted_bytes = selected_entry.current_password.clone();
    let decrypted_password = crypto.decrypt_string(&IVec::from(encrypted_bytes.clone()))
                                            .map_err(|e| format!("Decryption failed: {}", e))?;

    // 显示详细信息
    println!("\n--- Password Details ---");
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
