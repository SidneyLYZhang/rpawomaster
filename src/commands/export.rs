use crate::configtool::*;
use crate::securecrypto::SecureCrypto;
use crate::securecrypto::decrypt_private_key;
use std::path::Path;
use tempfile::tempdir;

pub fn export_vault(
    user: String,
    path: Option<String>,
    vault: Option<String>,
) -> Result<(), String> {
    let output_dir = match path {
        Some(p) => p,
        None => std::env::current_dir()
            .map(|dir| dir.to_string_lossy().into_owned())
            .unwrap_or_else(|_| ".".to_string()),
    };

    let core_password = prompt_core_password(user.clone())?;
    let username = get_username(Some(user.clone()))?.clone();
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
    
    let private_key = decrypt_private_key(&config.encrypted_private_key, &core_password)?;
    let crypto = SecureCrypto::from_pem_keys(&config.public_key, &private_key)
        .map_err(|e| format!("Failed to initialize crypto: {}", e))?;

    let export_dir = Path::new(&output_dir);
    if !export_dir.exists() {
        std::fs::create_dir_all(&export_dir)
            .map_err(|e| format!("创建导出目录失败: {}", e))?;
    }

    let export_filename = format!("{}.tgz", user);
    let export_path = export_dir.join(export_filename);

    let temp_dir = tempdir().map_err(|e| format!("创建临时文件夹失败: {}", e))?;
    let temp_path = temp_dir.path();
    for vault in &select_vaults {
        let src_path = Path::new(&vault.path);
        crypto.encrypt_path(src_path, temp_path)
                .map_err(|e| format!("加密Vault文件失败: {}", e))?;
    }
    let config_file_path = get_config_dir()?.join(format!("{}.json", user));
    let dest_config_path = temp_path.join(format!("{}.json", user));
    std::fs::copy(config_file_path, dest_config_path).map_err(|e| format!("复制配置文件失败: {}", e))?;

    crypto.create_tar_archive(
        temp_path,
        &export_path,
    ).map_err(|e| format!("创建加密归档失败: {}", e))?;

    println!("成功导出用户 '{}' 的数据到: {}", user, export_path.display());
    Ok(())
}
