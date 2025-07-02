//  ____  ____     __        __    __  __           _
// |  _ \|  _ \ __ \ \      / /__ |  \/  | __ _ ___| |_ ___ _ __ 
// | |_) | |_) / _` \ \ /\ / / _ \| |\/| |/ _` / __| __/ _ \ '__|
// |  _ <|  __/ (_| |\ V  V / (_) | |  | | (_| \__ \ ||  __/ |   
// |_| \_\_|   \__,_| \_/\_/ \___/|_|  |_|\__,_|___/\__\___|_|   
//
// Auther : Sidney Zhang <zly@lyzhang.me>
// Date : 2025-07-02
// Version : 0.1.0
// License : Mulan PSL v2
//
// Passwords Manager lib

use sled::{Db, IVec};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use bincode::serde::{encode_into_slice, decode_from_slice};
use bincode::config::standard;

// 密码生成策略配置
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PasswordPolicy {
    Random { length: u8, symbols: bool },
    Memorable { words: u8, separator: char },
    Pin { length: u8 },
    Custom(String),
}

// 密码历史记录
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasswordHistory {
    pub password: String,
    pub created_at: DateTime<Utc>,
    pub policy: Option<PasswordPolicy>,
}

// 主密码条目
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PasswordEntry {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub histories: Vec<PasswordHistory>, // 历史密码记录
    pub current_password: String,        // 当前密码 = histories.last()
    pub url: Option<String>,
    pub expires_at: Option<DateTime<Utc>>, // None 表示永不过期
    pub policy: Option<PasswordPolicy>,
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
        password: String,
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
            policy: policy.clone(),
        };

        let entry = PasswordEntry {
            id,
            name: name.clone(),
            username,
            histories: vec![history],
            current_password: password,
            url,
            expires_at,
            policy,
            note: note.clone(),
            created_at: now,
            updated_at: now,
        };

        // 序列化数据
        let mut serialized = [0u8; 100];
        encode_into_slice(&entry, &mut serialized, standard())?;
        
        // 获取密码树
        let passwords_tree = self.db.open_tree(Self::PASSWORDS_TREE)?;
        
        // 存储主数据
        passwords_tree.insert(id.as_bytes(), serialized.as_slice())?;
        
        // 更新索引
        self.update_index(IndexType::Name, &name, id)?;
        if let Some(note) = note {
            self.update_index(IndexType::Note, &note, id)?;
        }

        Ok(id)
    }

    /// 删除密码条目
    pub fn delete_password(&self, id: Uuid) -> Result<(), Box<dyn std::error::Error>> {
        let passwords_tree = self.db.open_tree(Self::PASSWORDS_TREE)?;
        
        if let Some(entry) = passwords_tree.get(id.as_bytes())? {
            let entry: PasswordEntry = decode_from_slice(&entry, standard())?.0;
            
            // 删除主记录
            passwords_tree.remove(id.as_bytes())?;
            
            // 删除索引
            self.remove_index(IndexType::Name, &entry.name, id)?;
            if let Some(note) = &entry.note {
                self.remove_index(IndexType::Note, note, id)?;
            }
        }
        
        Ok(())
    }

    /// 更新密码（保留历史记录）
    pub fn update_password(
        &self,
        id: Uuid,
        new_password: String,
        new_policy: Option<PasswordPolicy>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let passwords_tree = self.db.open_tree(Self::PASSWORDS_TREE)?;
        
        if let Some(entry) = passwords_tree.get(id.as_bytes())? {
            let mut entry: PasswordEntry = decode_from_slice(&entry, standard())?.0;
            let now = Utc::now();
            
            // 添加到历史记录
            let history = PasswordHistory {
                password: new_password.clone(),
                created_at: now,
                policy: new_policy.clone(),
            };
            
            entry.histories.push(history);
            entry.current_password = new_password;
            entry.policy = new_policy;
            entry.updated_at = now;
            
            // 保存更新
            let mut serialized = [0u8; 100];
            encode_into_slice(&entry, &mut serialized, standard())?;
            passwords_tree.insert(id.as_bytes(), serialized.as_slice())?;
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
            let entry: PasswordEntry = decode_from_slice(&value, standard())?.0;
            
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
                results.push(entry);
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
            entries.push(entry);
        }
        
        Ok(entries)
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
            let mut serialized = [0u8; 100];
            encode_into_slice(&ids, &mut serialized, standard())?;
            index_tree.insert(index_key, serialized.as_slice())?;
        }
        
        Ok(())
    }

    // 删除索引（内部方法）
    fn remove_index(
        &self,
        index_type: IndexType,
        key: &str,
        id: Uuid,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let index_tree = self.db.open_tree(Self::INDEX_TREE)?;
        let index_key = format!("{:?}:{}", index_type, key);
        
        if let Some(existing) = index_tree.get(&index_key)? {
            let mut ids: Vec<Uuid> = decode_from_slice(&existing, standard())?.0;
            
            // 移除ID
            if let Some(pos) = ids.iter().position(|x| *x == id) {
                ids.remove(pos);
                
                if ids.is_empty() {
                    index_tree.remove(index_key)?;
                } else {
                    let mut serialized = [0u8; 100];
                    encode_into_slice(&ids, &mut serialized, standard())?;
                    index_tree.insert(index_key, serialized.as_slice())?;
                }
            }
        }
        
        Ok(())
    }
}