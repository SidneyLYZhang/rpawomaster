use crate::configtool::*;
use crate::securecrypto::SecureCrypto;
use crate::securecrypto::decrypt_private_key;
use std::path::Path;
use tempfile::tempdir;

pub fn import_passvaults(filepath: String, vaultspath: String) -> Result<(), Box<dyn std::error::Error + 'static>> {
    let temp_dir = tempdir().map_err(|e| format!("Failed to create temp directory: {}", e))?;
    let temp_path = temp_dir.path();

    let file_path = Path::new(&filepath);
    {
        let crypto = SecureCrypto::new().map_err(|e| format!("Failed to create crypto: {}", e))?;
        crypto.extract_tar_archive(file_path, temp_path)?;
    }

    let username = file_path.file_stem().map(|s| s.to_string_lossy().to_string()).ok_or("Failed to get username from filepath")?;
    let config_path = get_config_dir()?;
    let config_file_path = config_path.join(format!("{}.json", &username));
    std::fs::copy(temp_path.join(format!("{}.json", &username)), config_file_path)?;

    let password = prompt_core_password(username.clone())?;

    let config = load_config(&username, &password)?;
    let private_key = decrypt_private_key(&config.encrypted_private_key, &password)?;
    let crypto = SecureCrypto::from_pem_keys(&config.public_key, &private_key)?;
    let vault_names = config.vaults.iter().map(|v| &v.name).collect::<Vec<_>>();
    for vault in vault_names {
        let encrypted_vault_path = temp_path.join(format!("{}.tgz.esz",vault));
        crypto.decrypt_path(encrypted_vault_path, vaultspath.clone())?;
    }
    Ok(())
}
