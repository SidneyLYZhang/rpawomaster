use crate::configtool::*;
use crate::pwsmanager;
use std::path::PathBuf;

pub fn list_passwords(user: Option<String>, vault: Option<String>) -> Result<(), String> {
    let username = get_username(user)?;
    let config = load_user_config(&username)?;
    let vault = select_vault(&config, vault)?;

    let vault_path_buf = PathBuf::from(&vault.path);
    if !vault_path_buf.exists() {
        return Err(format!("Vault directory not found: {}", vault.path));
    }

    let manager = pwsmanager::PasswordManager::new(&vault.path)
                                    .map_err(|e| format!("Failed to initialize password manager: {}", e))?;
    let entries = manager.list_passwords()
                                .map_err(|e| format!("Failed to list passwords: {}", e))?;

    println!("{:<10} | {:<10} | {:<40} | {:<30} | {:<5}", 
             "名称", "用户名", "URL", "说明", "有效期");
    println!("{}", "-".repeat(105));

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
}
