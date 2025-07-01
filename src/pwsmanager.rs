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
// Passwords Manager lib


use chrono::{Duration, Local};
use rand::rngs::OsRng;

use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};

use anyhow::anyhow;

// 密码生成策略配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordGenerationPolicy {
    pub include_uppercase: bool,
    pub include_lowercase: bool,
    pub include_numbers: bool,
    pub include_special_chars: bool,
    pub url_safe: bool,
    pub exclude_confusing_chars: bool,
    pub length: usize,
}

impl Default for PasswordGenerationPolicy {
    fn default() -> Self {
        PasswordGenerationPolicy {
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_special_chars: true,
            url_safe: false,
            exclude_confusing_chars: true,
            length: 16,
        }
    }
}

// 密码条目结构体
#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordEntry {
    pub id: u64,
    pub user_id: String,
    pub vault_id: String,
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub password_encrypted: String,
    pub expiry_date: Option<chrono::DateTime<Local>>,
    pub created_date: chrono::DateTime<Local>,
    pub note: Option<String>,
    pub generation_policy: PasswordGenerationPolicy,
}

// 命令选项结构体
#[derive(Debug)]
pub struct AddPasswordOptions {
    pub user: String,
    pub vault: Option<String>,
    pub name: String,
    pub username: Option<String>,
    pub url: Option<String>,
    pub expiry_days: i64,
    pub note: Option<String>,
    pub manual_password: Option<String>,
    pub generation_policy: Option<PasswordGenerationPolicy>,
}

#[derive(Debug)]
pub struct UpdatePasswordOptions {
    pub entry_id: u64,
    // 其他更新选项...
}

#[derive(Debug)]
pub struct DeletePasswordOptions {
    pub entry_id: u64,
    // 其他删除选项...
}

#[derive(Debug)]
pub struct FindPasswordOptions {
    pub name: Option<String>,
    pub url: Option<String>,
    // 其他查找选项...
}

/// 密码命令处理结构体
pub struct PasswordCommandHandler {
    db_path: String,
    public_key: RsaPublicKey,
}

impl PasswordCommandHandler {
    /// 创建密码命令处理器
    pub fn new(db_path: String, rsa_public_key: RsaPublicKey) -> Self {
        PasswordCommandHandler {
            db_path: db_path,
            public_key: rsa_public_key,
        }
    }
    /// 添加新密码
    /// 添加新密码条目到数据库
    /// 
    /// # 参数
    /// * `options` - 添加密码所需的选项
    /// 
    /// # 返回值
    /// 成功时返回创建的密码条目，失败时返回错误
    pub fn add_password(&self, options: AddPasswordOptions) -> Result<PasswordEntry> {
        // 获取密码库（必须由调用方指定）
        let vault_id = options.vault.ok_or(anyhow!("Vault must be specified"))?;
        
        // 获取密码（必须由调用方提供）
        let password = options.manual_password.ok_or(rusqlite::Error::Other("Password must be provided".to_string()))?;
        
        // 获取生成策略（必须由调用方提供）
        let generation_policy = options.generation_policy.ok_or(rusqlite::Error::Other("Generation policy must be provided".to_string()))?;
        
        // 加密密码
        let password_encrypted = self.encrypt_password(&password).map_err(|e| rusqlite::Error::Other(e))?;
        
        // 计算有效期
        let expiry_date = if options.expiry_days == 0 {
            None
        } else {
            Some(Local::now() + Duration::days(options.expiry_days as i64))
        };
        
        // 连接数据库并插入记录
        let conn = Connection::open(&self.db_path)?;
        let created_date = Local::now();
        
        const INSERT_PASSWORD_SQL: &str = "INSERT INTO password_entries (user_id, vault_id, name, username, url, password_encrypted, expiry_date, created_date, note, generation_policy) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) 
             RETURNING id";
        let mut stmt = conn.prepare(INSERT_PASSWORD_SQL)?;
        
        // 序列化生成策略
        let generation_policy_json = serde_json::to_string(&generation_policy)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        
        // 格式化日期为RFC3339字符串
        let format_date = |date: chrono::DateTime<Local>| date.to_rfc3339();
        let expiry_date_str = expiry_date.map(format_date);
        let created_date_str = format_date(created_date);
        
        // 执行插入并返回ID
        let id: u64 = stmt.query_row(
            params![
                options.user,
                vault_id,
                options.name,
                options.username,
                options.url,
                password_encrypted,
                expiry_date_str,
                created_date_str,
                options.note,
                generation_policy_json
            ],
            |row| row.get(0)
        )?;
        
        // 创建并返回密码条目
        Ok(PasswordEntry {
            id,
            user_id: options.user,
            vault_id,
            name: options.name,
            username: options.username,
            url: options.url,
            password_encrypted,
            expiry_date,
            created_date,
            note: options.note,
            generation_policy,
        })
    }

    /// 更新密码（创建新版本）
    pub fn update_password(&self, _options: UpdatePasswordOptions) -> Result<PasswordEntry> {
        // TODO: 实现密码更新逻辑
        // 1. 查找现有记录获取生成策略
        // 2. 使用相同策略生成新密码
        // 3. 创建新的密码记录
        // 4. 返回新创建的记录
        unimplemented!()
    }

    /// 删除密码
    pub fn delete_password(&self, _options: DeletePasswordOptions) -> Result<()> {
        // TODO: 实现密码删除逻辑
        unimplemented!()
    }

    /// 查找密码
    pub fn find_passwords(&self, _options: FindPasswordOptions) -> Result<Vec<PasswordEntry>> {
        // TODO: 实现密码查找逻辑
        unimplemented!()
    }

    /// 加密密码
    fn encrypt_password(&self, password: &str) -> Result<String, String> {
        let mut rng = OsRng;

        // 执行RSA加密并处理错误
        let encrypted_data = self.public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, password.as_bytes())
            .map_err(|e| rusqlite::Error(format!("Encryption failed: {{}}", e)))?;

        // 将加密后的字节数据转换为十六进制字符串
        Ok(hex::encode(encrypted_data))
    }
}

/// 初始化数据库表结构
pub fn init_database(db_path: &str) -> Result<()> {
    let conn = Connection::open(db_path)?;
    
    conn.execute(
        "CREATE TABLE IF NOT EXISTS password_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            vault_id TEXT NOT NULL,
            name TEXT NOT NULL,
            username TEXT,
            url TEXT,
            password_encrypted TEXT NOT NULL,
            expiry_date TEXT,
            created_date TEXT NOT NULL,
            note TEXT,
            generation_policy TEXT NOT NULL,
            UNIQUE(user_id, vault_id, name)
        )",
        [],
    )?;
    
    Ok(())
}