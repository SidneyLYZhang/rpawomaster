//  ____  ____     __        __    __  __           _
// |  _ \|  _ \ __ \ \      / /__ |  \/  | __ _ ___| |_ ___ _ __ 
// | |_) | |_) / _` \ \ /\ / / _ \| |\/| |/ _` / __| __/ _ \ '__|
// |  _ <|  __/ (_| |\ V  V / (_) | |  | | (_| \__ \ ||  __/ |   
// |_| \_\_|   \__,_| \_/\_/ \___/|_|  |_|\__,_|___/\__\___|_|   
//
// Author : Sidney Zhang <zly@lyzhang.me>
// Date : 2025-07-02
// Version : 0.1.0
// License : Mulan PSL v2
//
// Passwords Manager lib

use sled::{Db};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use bincode::serde::{encode_into_slice, decode_from_slice};
use bincode::config::standard;
use crate::passgen::Capitalization;
use crate::xotp::XOTP;

// 密码生成策略配置
#[derive(Serialize, Deserialize, Clone, Debug, bincode::Encode, bincode::Decode)]
pub enum PasswordPolicy {
    Random {
        length: usize,
        include_uppercase: bool,
        include_lowercase: bool,
        include_numbers: bool,
        include_special: bool,
        url_safe: bool,
        avoid_confusion: bool
    },
    Memorable {
        words: u8,
        separator: char,
        include_numbers: bool,
        capitalization: Capitalization
    },
}

// 密码历史记录
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasswordHistory {
    pub password: Vec<u8>,
    pub created_at: DateTime<Utc>
}

// 主密码条目
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasswordEntry {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub histories: Vec<PasswordHistory>, // 历史密码记录
    pub current_password: Vec<u8>,        // 当前密码 = histories.last()
    pub url: Option<String>,
    pub expires_at: Option<DateTime<Utc>>, // None 表示永不过期
    pub policy: Option<PasswordPolicy>,
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted: bool,
}

impl PasswordEntry {
    pub fn need_update(&self) -> bool {
        if self.deleted {
            return false;
        } else if self.expires_at.is_some() {
            let now = Utc::now();
            let expires_at = self.expires_at.unwrap();
            if now > expires_at {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OtpEntry {
    pub id: Uuid,
    pub secretdata: XOTP,
    pub created_at: DateTime<Utc>,
}

// 索引类型枚举
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Debug)]
enum IndexType {
    Name,
    Note,
}

// 密码管理器主体
pub struct PasswordManager {
    db: Db,
}

impl PasswordManager {
    const PASSWORDS_TREE: &'static str = "passwords";
    const INDEX_TREE: &'static str = "index";
    const XOTP_TREE: &'static str = "xotp";

    /// 初始化密码管理器
    pub fn new(db_path: &str) -> Result<Self, sled::Error> {
        let db = sled::open(db_path)?;
        Ok(PasswordManager { db })
    }

    /// 添加新密码条目
    pub fn add_password(
        &self,
        name: String,
        username: Option<String>,
        password: Vec<u8>,
        url: Option<String>,
        expires_in_days: u32, // 0 表示永不过期
        policy: Option<PasswordPolicy>,
        note: Option<String>,
    ) -> Result<Uuid, Box<dyn std::error::Error>> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        
        let expires_at = if expires_in_days > 0 {
            Some(now + chrono::Duration::days(expires_in_days as i64))
        } else {
            None
        };
        let history = PasswordHistory {
            password: password.clone(),
            created_at: now,
        };

        let entry = PasswordEntry {
            id,
            name: name.clone(),
            username,
            histories: vec![history],
            current_password: password.clone(),
            url,
            expires_at,
            policy,
            note: note.clone(),
            created_at: now,
            updated_at: now,
            deleted: false,
        };

        // 序列化数据
        let mut buffer = vec![0u8; 1024]; // 初始化一个足够大的缓冲区
        encode_into_slice(&entry, &mut buffer, standard())?;
        let serialized = &buffer[..];
        
        // 获取密码树
        let passwords_tree = self.db.open_tree(Self::PASSWORDS_TREE)?;
        
        // 存储主数据
        passwords_tree.insert(id.as_bytes(), serialized)?;
        
        // 更新索引
        self.update_index(IndexType::Name, &name, id)?;
        if let Some(note) = note {
            self.update_index(IndexType::Note, &note, id)?;
        }

        Ok(id)
    }

    /// 删除密码条目
    pub fn delete_password(
        &self, 
        id: Option<Uuid>, 
        name: Option<String>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let passwords_tree = self.db.open_tree(Self::PASSWORDS_TREE)?;

        let id = match id {
            Some(id) => id,
            None => self.get_uuid(name.as_ref().unwrap())?,
        };
        
        if let Some(entry) = passwords_tree.get(id.as_bytes())? {
            let mut entry: PasswordEntry = bincode::serde::decode_from_slice(&entry, standard())?.0;
            
            // 标记为已删除
            entry.deleted = true;
            
            // 保存更新
            let mut buffer = vec![0u8; 1024]; // 初始化一个足够大的缓冲区
            encode_into_slice(&entry, &mut buffer, standard())?;
            let serialized = &buffer[..];
            passwords_tree.insert(id.as_bytes(), serialized)?;
        }
        
        Ok(())
    }

    /// 获取密码数据
    pub fn get_password(
        &self,
        id: Option<Uuid>,
        expired: Option<bool>,
    ) -> Result<Vec<PasswordEntry>, Box<dyn std::error::Error>> {
        let expired = expired.unwrap_or(false);
        let passwords_tree = self.db.open_tree(Self::PASSWORDS_TREE)?;
        if expired {
            let mut entries = Vec::new();
            for record in passwords_tree.iter() {
                let (_, value) = record?;
                let entry: PasswordEntry = bincode::serde::decode_from_slice(&value, standard())?.0;
                if entry.need_update() {
                    entries.push(entry);
                }
            }
            Ok(entries)
        } else {
            let id = id.ok_or("Password Id must be specified")?;
            if let Some(entry) = passwords_tree.get(id.as_bytes())? {
                let entry: PasswordEntry = bincode::serde::decode_from_slice(&entry, standard())?.0;
                Ok(vec![entry])
            } else {
                Err("Password Id is wrong".into())
            }
        }
    }

    /// 更新密码（保留历史记录）
    pub fn update_password(
        &self,
        id: Uuid,
        new_password: Vec<u8>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let passwords_tree = self.db.open_tree(Self::PASSWORDS_TREE)?;
        
        if let Some(entry) = passwords_tree.get(id.as_bytes())? {
            let mut entry: PasswordEntry = bincode::serde::decode_from_slice(&entry, standard())?.0;
            let now = Utc::now();

            // 添加到历史记录
            let history = PasswordHistory {
                password: new_password.clone(),
                created_at: now,
            };
            
            entry.histories.push(history);
            entry.current_password = new_password;
            entry.updated_at = now;
            
            // 保存更新
            let mut buffer = vec![0u8; 1024]; // 初始化一个足够大的缓冲区
            encode_into_slice(&entry, &mut buffer, standard())?;
            let serialized = &buffer[..];
            passwords_tree.insert(id.as_bytes(), serialized)?;
        }
        
        Ok(())
    }

    /// 查询密码（支持模糊和精确查询）
    pub fn find_passwords(
        &self,
        query: &str,
        exact_match: bool,
    ) -> Result<Vec<PasswordEntry>, Box<dyn std::error::Error>> {
        let passwords_tree = self.db.open_tree(Self::PASSWORDS_TREE)?;
        let mut results = Vec::new();
        
        for record in passwords_tree.iter() {
            let (_, value) = record?;
            let entry: PasswordEntry = bincode::serde::decode_from_slice(&value, standard())?.0;
            
            // 检查名称和备注
            let name_match = if exact_match {
                entry.name == query
            } else {
                entry.name.contains(query)
            };
            
            let note_match = entry.note.as_ref().map_or(false, |n| {
                if exact_match {
                    n == query
                } else {
                    n.contains(query)
                }
            });
            
            if name_match || note_match {
                // 过滤掉已删除的条目
                if !entry.deleted {
                    results.push(entry);
                }
            }
        }
        
        Ok(results)
    }

    /// 列出所有密码
    pub fn list_passwords(&self) -> Result<Vec<PasswordEntry>, Box<dyn std::error::Error>> {
        let passwords_tree = self.db.open_tree(Self::PASSWORDS_TREE)?;
        let mut entries = Vec::new();
        
        for record in passwords_tree.iter() {
            let (_, value) = record?;
            let entry: PasswordEntry = decode_from_slice(&value, standard())?.0;
            // 过滤掉已删除的条目
            if !entry.deleted {
                entries.push(entry);
            }
        }
        
        Ok(entries)
    }

    // 获取Uuid
    pub fn get_uuid(&self, key: &str) -> Result<Uuid, Box<dyn std::error::Error>> {
        let index_tree = self.db.open_tree(Self::INDEX_TREE)?;
        let index_key = format!("{:?}:{}", IndexType::Name, key);
        if let Some(existing) = index_tree.get(&index_key)? {
            let ids: Vec<Uuid> = decode_from_slice(&existing, standard())?.0;
            if ids.is_empty() {
                return Err("No UUID found for the given index type and key".into());
            }
            Ok(ids[0])
        } else {
            Err("No UUID found for the given index type and key".into())
        }
    }

    // 获取UUID对应的PasswordEntry
    pub fn get_password_entry(
        &self,
        id: Uuid,
    ) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
        let passwords_tree = self.db.open_tree(Self::PASSWORDS_TREE)?;
        if let Some(entry) = passwords_tree.get(id.as_bytes())? {
            let entry: PasswordEntry = bincode::serde::decode_from_slice(&entry, standard())?.0;
            Ok(entry)
        } else {
            Err("No PasswordEntry found for the given UUID".into())
        }
    }

    // 更新索引（内部方法）
    fn update_index(
        &self,
        index_type: IndexType,
        key: &str,
        id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let index_tree = self.db.open_tree(Self::INDEX_TREE)?;
        let index_key = format!("{:?}:{}", index_type, key);
        
        // 获取现有索引或创建新索引
        let mut ids = if let Some(existing) = index_tree.get(&index_key)? {
            decode_from_slice(&existing, standard())?.0
        } else {
            Vec::new()
        };
        
        // 添加新ID
        if !ids.contains(&id) {
            ids.push(id);
            let serialized = bincode::serde::encode_to_vec(&ids, standard())?;
            index_tree.insert(index_key, serialized.as_slice())?;
        }
        
        Ok(())
    }

    /// 添加OTP
    pub fn add_otp(
        &self,
        id: Uuid,
        otp: XOTP,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let xotp_tree = self.db.open_tree(Self::XOTP_TREE)?;
        let otp_entry = OtpEntry {
            id: id.clone(),
            secretdata: otp,
            created_at: Utc::now(),
        };
        let serialized = bincode::serde::encode_to_vec(&otp_entry, standard())?;
        xotp_tree.insert(id.clone(), serialized.as_slice())?;
        Ok(())
    }

    /// List OTP
    pub fn list_otp(
        &self,
    ) -> Result<Vec<OtpEntry>, Box<dyn std::error::Error>> {
        let xotp_tree = self.db.open_tree(Self::XOTP_TREE)?;
        let mut entries = Vec::new();
        for record in xotp_tree.iter() {
            let (_, value) = record?;
            let entry: OtpEntry = bincode::serde::decode_from_slice(&value, standard())?.0;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// 获取OTP
    pub fn get_otp(
        &self,
        id: Uuid,
    ) -> Result<Option<XOTP>, Box<dyn std::error::Error>> {
        let xotp_tree = self.db.open_tree(Self::XOTP_TREE)?;
        if let Some(entry) = xotp_tree.get(id.as_bytes())? {
            let otp_entry: OtpEntry = bincode::serde::decode_from_slice(&entry, standard())?.0;
            Ok(Some(otp_entry.secretdata))
        } else {
            Ok(None)
        }
    } 
}