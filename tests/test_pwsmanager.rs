use rpawomaster::pwsmanager::{PasswordManager, PasswordPolicy};
// use sled;
use uuid::Uuid;
// use chrono::{DateTime, Utc, Duration};
// use serde::{Serialize, Deserialize};
use tempfile::tempdir;

// 创建测试用PasswordManager（使用临时数据库）
fn test_manager() -> PasswordManager {
    let dir = tempdir().expect("Failed to create temp directory");
    PasswordManager::new(dir.path().to_str().unwrap()).expect("Failed to create PasswordManager")
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
    manager.update_password(id, new_password.clone()).unwrap();

    // 验证更新结果
    let entries = manager.list_passwords().unwrap();
    assert_eq!(entries[0].current_password, new_password);
    assert_eq!(entries[0].histories.len(), 2);
    assert_eq!(entries[0].histories[0].password, initial_password);
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
    manager.delete_password(Some(id), None).unwrap();

    // 验证删除成功
    assert_eq!(manager.list_passwords().unwrap().len(), 0);

    // 尝试删除不存在的ID（应该不报错）
    let non_existent_id = Uuid::new_v4();
    assert!(manager.delete_password(Some(non_existent_id), None).is_ok());
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
    manager.update_password(id, password2.clone()).unwrap();
    manager.update_password(id, password3.clone()).unwrap();

    // 验证历史记录
    let entries = manager.list_passwords().unwrap();
    assert_eq!(entries[0].histories.len(), 3);
    assert_eq!(entries[0].histories[0].password, password1);
    assert_eq!(entries[0].histories[1].password, password2);
    assert_eq!(entries[0].histories[2].password, password3);
    assert_eq!(entries[0].current_password, password3);
}