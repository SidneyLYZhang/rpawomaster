//  ____  ____     __        __    __  __           _
// |  _ \|  _ \ __ \ \      / /__ |  \/  | __ _ ___| |_ ___ _ __ 
// | |_) | |_) / _` \ \/\ / / _ \| |\/| |/ _` / __| __/ _ \ '__|
// |  _ <|  __/ (_| |\ V  V / (_) | |  | | (_| \__ \ ||  __/ |   
// |_| \_\_|   \__,_| \_/\_/ \___/|_|  |_|\__,_|___/\__\___|_|   
//
// Author : Sidney Zhang <zly@lyzhang.me>
// Date : 2025-07-30
// Version : 0.1.8
// License : Mulan PSL v2
//
// Config Tools

use rand::{RngCore, rngs::OsRng};
use hmac::Hmac;
use hex::encode;
use aes_gcm::{Aes256Gcm, AeadInPlace, KeyInit, Nonce};

use serde::{Serialize, Deserialize};
use serde_json;
use std::{fs, path::{Path, PathBuf}};
use dirs::config_dir;
use chrono::{DateTime, Utc};
use pbkdf2::pbkdf2;
use sha2::Sha256;
use std::{fmt, io::{self, Write}};
use rpassword::read_password;

use crate::securecrypto::generate_rsa_keypair;
use crate::passgen::assess_password_strength;

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultMetadata {
    pub name: String,
    pub path: String,
    pub created_at: String,
    pub last_modified: String,
}

impl VaultMetadata {
    pub fn get_vaultmetadata(vaultpath: &str) -> Result<Self, ConfigError> {
        let metadata_path = Path::new(vaultpath).join("metadata.json");
        let metadata_file = fs::File::open(&metadata_path)
            .map_err(|e| format!("Failed to open metadata file: {}", e)).unwrap();
        let metadata: Self = serde_json::from_reader(metadata_file)
            .map_err(|e| format!("Failed to read metadata file: {}", e)).unwrap();
        Ok(metadata)
    }
    pub fn from_vault(vault: &Vault) -> Self {
        Self {
            name: vault.name.clone(),
            path: vault.path.clone(),
            created_at: vault.created_at.clone(),
            last_modified: vault.last_modified.clone(),
        }
    }
    pub fn save_vaultmetadata(&self) -> Result<(), ConfigError> {
        let metadata_path = Path::new(&self.path).join("metadata.json");
        let metadata_file = fs::File::create(&metadata_path)
            .map_err(|e| format!("Failed to create metadata file: {}", e)).unwrap();
        serde_json::to_writer_pretty(metadata_file, &self)
            .map_err(|e| format!("Failed to write metadata file: {}", e)).unwrap();
        Ok(())
    }
    pub fn vault_updated(&mut self) {
        self.last_modified = Utc::now().to_rfc3339();
        self.save_vaultmetadata().unwrap();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub name: String,
    pub path: String,
    pub is_default: bool,
    pub created_at: String,
    pub last_modified: String,
}

impl Vault {
    pub fn new(name: &str, path: &str, is_default: Option<bool>) -> Self {
        let timenow = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        Self {
            name: name.to_string(),
            path: path.to_string(),
            is_default: is_default.unwrap_or(false),
            created_at: timenow.clone(),
            last_modified: timenow.clone(),
        }
    }
    pub fn set_default(&mut self, is_default: bool) {
        self.is_default = is_default;
        self.last_modified = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    }
    pub fn update_vault(&mut self) {
        let mut metadata = VaultMetadata::from_vault(self);
        metadata.vault_updated();
        self.last_modified = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    }
}

#[derive(Debug)]
pub enum ConfigError {
    IoError(std::io::Error),
    JsonError(serde_json::Error),
    ConfigDirError(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::IoError(e) => write!(f, "IO error: {}", e),
            ConfigError::JsonError(e) => write!(f, "JSON error: {}", e),
            ConfigError::ConfigDirError(msg) => write!(f, "Config directory error: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigFile {
    pub username: String,
    pub encrypted_private_key: String,
    pub public_key: String,
    pub vaults: Vec<Vault>,
    pub core_password_update_time: DateTime<Utc>,
}

impl ConfigFile {
    pub fn new(username: &str, encrypted_private_key: &str, public_key: &str) -> Self {
        Self {
            username: username.to_string(),
            encrypted_private_key: encrypted_private_key.to_string(),
            public_key: public_key.to_string(),
            vaults: Vec::new(),
            core_password_update_time: Utc::now(),
        }
    }
    pub fn add_vault(&mut self, vault: Vault) {
        self.vaults.push(vault);
        self.save_config().unwrap();
    }
    pub fn update_vault(&mut self, vault: Vault) {
        for v in &mut self.vaults {
            if v.path == vault.path {
                *v = vault;
                break;
            }
        }
        self.save_config().unwrap();
    }
    pub fn save_config(&self) -> Result<(), ConfigError> {
        let config_dir = get_config_dir().map_err(ConfigError::ConfigDirError)?;
        let config_file_path = config_dir.join(format!("{}.json", self.username));
        fs::create_dir_all(&config_dir)
            .map_err(ConfigError::IoError)?;
        let config_file = fs::File::create(&config_file_path)
            .map_err(ConfigError::IoError)?;
        serde_json::to_writer_pretty(config_file, &self)
            .map_err(ConfigError::JsonError)?;
        Ok(())
    }
    pub fn get_private_key(&self, password: &str) -> Result<String, String> {
        let key = self.encrypted_private_key.clone();
        let private_key = decrypt_private_key(&key, password)?;
        Ok(private_key)
    }
    pub fn check_corepassword_valid(&mut self, password: &str) -> Result<String, String> {
        let now = Utc::now();
        let daygap = now.signed_duration_since(self.core_password_update_time).num_days();
        let new_password = if daygap >= 90 { // core password 强制90天有效
            loop {
                println!("⚠️ Core password has expired.");
                let new_core_password = read_password_from_stdin("Enter new core password: ")?;
                let confirm = read_password_from_stdin("Confirm new core password: ")?;
                if new_core_password != confirm {
                    println!("New Core Passwords do not match. Please try again.");
                    continue;
                }
                let (rating, score, feedback) = assess_password_strength(&new_core_password)?;
                if score < 3 {
                    println!("Warning: Weak core password. {}", feedback);
                    println!("New Core Password is {} ({}/4). Please try again.", rating, score);
                    continue;
                }
                let private_key = self.get_private_key(password)?;
                self.encrypted_private_key = encrypt_private_key(&private_key,&new_core_password)?;
                self.core_password_update_time = now;
                self.save_config().unwrap();
                break new_core_password;
            }
        } else {
            password.to_string()
        };
        Ok(new_password)
    }
}

/// 提示用户输入
pub fn prompt_input(prompt: &str) -> Result<String, String> {
    print!("{}", prompt);
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    Ok(input.trim().to_string())
}

/// 提示用户输入密码
pub fn read_password_from_stdin(prompt: &str) -> Result<String, String> {
    print!("{}", prompt);
    io::stdout().flush().map_err(|e| format!("Failed to flush output: {}", e))?;
    read_password().map_err(|e| format!("Failed to read password: {}", e))
}

/// 提示用户输入核心密码，并核心密码验证
pub fn prompt_core_password(user: String) -> Result<String, String> {
    let mut core_password = read_password_from_stdin("Enter core password: ")?;
    let mut config = load_user_config(&user)?;
    core_password = config.check_corepassword_valid(&core_password)?;
    Ok(core_password)
}

/// 获取配置目录
pub fn get_config_dir() -> Result<PathBuf, String> {
    match config_dir() {
        Some(path) => Ok(path.join("rpawomaster")),
        None => Err("Could not determine configuration directory".to_string()),
    }
}

/// 加载配置文件
pub fn load_config(username: &str, password: &str) -> Result<ConfigFile, String> {
    if check_user_exist(username)? {
        // Get config directory
        let config_dir = get_config_dir()?;
        let config_file_path = config_dir.join(format!("{}.json", username));

        if !config_file_path.exists() {
            return Err(format!("Configuration file for user '{}' not found. Please run 'init' first.", username));
        }

        let config_data = fs::read_to_string(&config_file_path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;

        // Return ConfigFile Info
        serde_json::from_str(&config_data)
            .map_err(|e| format!("Failed to parse config file: {}", e))
    } else {
        // user is not exist
        println!("Generating RSA key pair...");
        let (private_key, public_key) = generate_rsa_keypair()?;
        println!("Encrypting private key...");
        let encrypted_private_key = encrypt_private_key(&private_key, password)?;
        Ok(ConfigFile::new(username, &encrypted_private_key, &public_key))
    }
}

pub fn check_user_exist(username: &str) -> Result<bool, String> {
    let config_dir = get_config_dir()?;
    let config_file_path = config_dir.join(format!("{}.json", username));
    Ok(config_file_path.exists())
}

/// 加密私钥
pub fn encrypt_private_key(private_key: &str, core_password: &str) -> Result<String, String> {
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

/// 解密私钥
pub fn decrypt_private_key(encrypted_private_key: &str, core_password: &str) -> Result<String, String> {
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

/// 获取用户名，如果提供了user参数则直接使用，否则提示用户输入
pub fn get_username(user: Option<String>) -> Result<String, String> {
    match user {
        Some(u) => Ok(u),
        None => {
            print!("Enter username: ");
            io::stdout().flush().map_err(|e| e.to_string())?;
            let mut input = String::new();
            io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
            let input = input.trim();
            if input.is_empty() {
                return Err("Username cannot be empty".to_string());
            }
            Ok(input.to_string())
        }
    }
}

/// 加载用户配置
pub fn load_user_config(username: &str) -> Result<ConfigFile, String> {
    let config_dir = get_config_dir()?;
    let config_file_path = config_dir.join(format!("{}.json", username));
    if !config_file_path.exists() {
        return Err(format!("No configuration found for user '{}'", username));
    }
    let config_data = fs::read_to_string(&config_file_path)
        .map_err(|e| format!("Failed to read config file: {}", e))?;
    let config: ConfigFile = serde_json::from_str(&config_data)
        .map_err(|e| format!("Failed to parse config file: {}", e))?;
    Ok(config)
}

// 选取密码库
pub fn select_vault(config: &ConfigFile, vault_arg: Option<String>) -> Result<Vault, String> {
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

// 输入密码并完成一般密码的确认
pub fn input_password_check() -> Result<String, String> {
    loop {
        let password = read_password_from_stdin("Enter new password: ")?;
        let confirm = read_password_from_stdin("Confirm new password: ")?;
        if password != confirm {
            println!("Passwords do not match. Please try again.");
            continue;
        }
        let (rating, score,feedback) = assess_password_strength(&password)?;
        if score < 2 {
            println!("⚠️ 警告: 密码安全等级较低 - {}", feedback);
            let retry = prompt_input("Do you want to try again? (Y/n): ")?;
            if retry.trim().is_empty() {
                continue;
            } else {
                if retry.trim().to_lowercase() != "n" {
                    continue;
                } else {
                    println!("⭐ 密码安全等级: {} ({}/4)", rating, score);
                    break Ok(password);
                }
            }
        }
        break Ok(password);
    }
}