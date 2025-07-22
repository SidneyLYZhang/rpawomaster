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
use crate::passgen::{generate_password, generate_memorable_password, PasswordOptions, MemorablePasswordOptions};

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
    pub fn delete_password(&self, id: Uuid) -> Result<(), Box<dyn std::error::Error>> {
        let passwords_tree = self.db.open_tree(Self::PASSWORDS_TREE)?;
        
        if let Some(entry) = passwords_tree.get(id.as_bytes())? {
            let entry: PasswordEntry = bincode::serde::decode_from_slice(&entry, standard())?.0;
            
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
        new_password: Option<Vec<u8>>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let passwords_tree = self.db.open_tree(Self::PASSWORDS_TREE)?;
        
        if let Some(entry) = passwords_tree.get(id.as_bytes())? {
            let mut entry: PasswordEntry = bincode::serde::decode_from_slice(&entry, standard())?.0;
            let now = Utc::now();
            
            let new_password = match new_password {
                Some(p) => p,
                None => {
                    let policy = entry.policy.clone().ok_or("Password policy must be specified")?;
                    self.generate_from_policy(&policy)?
                }
            };

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
            let serialized = bincode::serde::encode_to_vec(&ids, standard())?;
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

    fn generate_from_policy(&self, policy: &PasswordPolicy) -> Result<Vec<u8>, String> {
        match policy {
            PasswordPolicy::Random { length, include_uppercase, include_lowercase, include_numbers, include_special, url_safe, avoid_confusion } => {
                let options = PasswordOptions {
                    length: *length,
                    include_uppercase: *include_uppercase,
                    include_lowercase: *include_lowercase,
                    include_numbers: *include_numbers,
                    include_special: *include_special,
                    url_safe: *url_safe,
                    avoid_confusion: *avoid_confusion,
                };
                generate_password(&options).map(|s| s.into_bytes())
            }
            PasswordPolicy::Memorable { words, separator, include_numbers, capitalization } => {
                let options = MemorablePasswordOptions {
                    word_count: *words as usize,
                    separator: *separator,
                    include_numbers: *include_numbers,
                    capitalization: capitalization.clone(),
                };
                generate_memorable_password(&options).map(|s| s.into_bytes())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sled;
    use uuid::Uuid;

    // 创建测试用PasswordManager（使用内存数据库）
    fn test_manager() -> PasswordManager {
        let db = sled::open("memory://test_db").expect("Failed to open test database");
        PasswordManager { db }
    }

    #[test]
    fn test_add_password() {
        let manager = test_manager();
        let password = b"test_password".to_vec();

        // 添加密码条目
        let id = manager.add_password(
            "Test Account".to_string(),
            Some("user@example.com".to_string()),
            password.clone(),
            Some("https://example.com".to_string()),
            30, // 30天后过期
            Some(PasswordPolicy::Random {
                length: 16,
                include_uppercase: true,
                include_lowercase: true,
                include_numbers: true,
                include_special: true,
                url_safe: false,
                avoid_confusion: true
            }),
            Some("Test note".to_string()),
        ).expect("Failed to add password");

        // 验证添加成功
        let entries = manager.list_passwords().expect("Failed to list passwords");
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.id, id);
        assert_eq!(entry.name, "Test Account");
        assert_eq!(entry.username, Some("user@example.com".to_string()));
        assert_eq!(entry.current_password, password);
        assert!(entry.expires_at.is_some());
    }

    #[test]
    fn test_find_passwords() {
        let manager = test_manager();
        let password = b"test_password".to_vec();

        // 添加测试数据
        manager.add_password(
            "GitHub Account".to_string(),
            Some("github_user".to_string()),
            password.clone(),
            Some("https://github.com".to_string()),
            0, // 永不过期
            None,
            Some("GitHub credentials".to_string()),
        ).unwrap();

        manager.add_password(
            "GitLab Account".to_string(),
            Some("gitlab_user".to_string()),
            password.clone(),
            Some("https://gitlab.com".to_string()),
            0,
            None,
            Some("GitLab credentials".to_string()),
        ).unwrap();

        // 精确匹配查询
        let exact_results = manager.find_passwords("GitHub Account", true).unwrap();
        assert_eq!(exact_results.len(), 1);
        assert_eq!(exact_results[0].name, "GitHub Account");

        // 模糊匹配查询
        let fuzzy_results = manager.find_passwords("Git", false).unwrap();
        assert_eq!(fuzzy_results.len(), 2);

        // 按备注查询
        let note_results = manager.find_passwords("GitHub", false).unwrap();
        assert_eq!(note_results.len(), 1);
    }

    #[test]
    fn test_update_password() {
        let manager = test_manager();
        let initial_password = b"initial_password".to_vec();
        let new_password = b"new_password123".to_vec();

        // 添加初始密码
        let id = manager.add_password(
            "Update Test".to_string(),
            None,
            initial_password.clone(),
            None,
            0,
            Some(PasswordPolicy::Random {
                length: 12,
                include_uppercase: true,
                include_lowercase: true,
                include_numbers: true,
                include_special: false,
                url_safe: true,
                avoid_confusion: true
            }),
            None,
        ).unwrap();

        // 验证初始密码
        let entries = manager.list_passwords().unwrap();
        assert_eq!(entries[0].current_password, initial_password);
        assert_eq!(entries[0].histories.len(), 1);

        // 更新密码（提供新密码）
        manager.update_password(id, Some(new_password.clone())).unwrap();

        // 验证更新结果
        let entries = manager.list_passwords().unwrap();
        assert_eq!(entries[0].current_password, new_password);
        assert_eq!(entries[0].histories.len(), 2);
        assert_eq!(entries[0].histories[0].password, initial_password);

        // 使用策略生成新密码
        manager.update_password(id, None).unwrap();
        let entries = manager.list_passwords().unwrap();
        assert_ne!(entries[0].current_password, new_password); // 应该不同
        assert_eq!(entries[0].histories.len(), 3);
    }

    #[test]
    fn test_delete_password() {
        let manager = test_manager();
        let password = b"delete_me".to_vec();

        // 添加测试密码
        let id = manager.add_password(
            "Delete Test".to_string(),
            None,
            password.clone(),
            None,
            0,
            None,
            None,
        ).unwrap();

        // 验证添加成功
        assert_eq!(manager.list_passwords().unwrap().len(), 1);

        // 删除密码
        manager.delete_password(id).unwrap();

        // 验证删除成功
        assert_eq!(manager.list_passwords().unwrap().len(), 0);

        // 尝试删除不存在的ID（应该不报错）
        let non_existent_id = Uuid::new_v4();
        assert!(manager.delete_password(non_existent_id).is_ok());
    }

    #[test]
    fn test_password_history() {
        let manager = test_manager();
        let password1 = b"version1".to_vec();
        let password2 = b"version2".to_vec();
        let password3 = b"version3".to_vec();

        // 添加初始密码
        let id = manager.add_password(
            "History Test".to_string(),
            None,
            password1.clone(),
            None,
            0,
            None,
            None,
        ).unwrap();

        // 多次更新密码
        manager.update_password(id, Some(password2.clone())).unwrap();
        manager.update_password(id, Some(password3.clone())).unwrap();

        // 验证历史记录
        let entries = manager.list_passwords().unwrap();
        assert_eq!(entries[0].histories.len(), 3);
        assert_eq!(entries[0].histories[0].password, password1);
        assert_eq!(entries[0].histories[1].password, password2);
        assert_eq!(entries[0].histories[2].password, password3);
        assert_eq!(entries[0].current_password, password3);
    }
}