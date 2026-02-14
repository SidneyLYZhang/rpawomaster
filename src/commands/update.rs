use crate::configtool::*;
use crate::pwsmanager;
use crate::securecrypto::SecureCrypto;
use crate::securecrypto::decrypt_private_key;
use crate::passgen::generate_from_policy;

pub fn update_password(
    all: Option<bool>,
    passwordname: Option<String>,
    user: Option<String>,
    vault: Option<String>,
) -> Result<(), String> {
    let need_all = all.unwrap_or(false);
    let username = get_username(user)?;
    let core_password = prompt_core_password(username.clone())?;
    let mut config = load_user_config(&username)?;
    let mut vault = select_vault(&config, vault)?;
    let private_key = decrypt_private_key(&config.encrypted_private_key, &core_password)?;
    let crypto = SecureCrypto::from_pem_keys(&config.public_key, &private_key)
                                            .map_err(|e| format!("Failed to create crypto object: {}", e))?;
    let pm = pwsmanager::PasswordManager::new(&vault.path)
                                    .map_err(|e| format!("Failed to initialize password manager: {}", e))?;
    if need_all {
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
        let pwname = match passwordname {
            Some(name) => name,
            None => prompt_input("Enter password name to update: ")?,
        };
        let id = pm.get_uuid(pwname.as_ref())
                            .map_err(|e| format!("Failed to find password {}: {}", pwname, e))?;
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
}
