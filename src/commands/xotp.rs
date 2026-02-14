use crate::configtool::*;
use crate::securecrypto::SecureCrypto;
use crate::pwsmanager::PasswordManager;
use crate::xotp::XOTP;

pub fn add_otp(
    name: String,
    user: Option<String>,
    vault: Option<String>,
    secret: String,
) -> Result<(), String> {
    let user = get_username(user)?;
    let core_password = prompt_core_password(user.clone())?;
    let config = load_config(&user, &core_password)?;
    let vault = select_vault(&config, vault)?;
    let mut vault_metadata = VaultMetadata::get_vaultmetadata(&vault.path).unwrap();
    let (private_key, public_key) = vault_metadata.get_keypair();
    let secure_crypto = SecureCrypto::from_pem_keys(&public_key, &private_key)
                                        .map_err(|e| format!("Failed to initialize crypto: {}", e))?;
    let otp = XOTP::from_text(&secret, &secure_crypto);
    let pw = PasswordManager::new(&vault.path)
                                                .map_err(|e| e.to_string())?;
    let uuid = pw.get_uuid(&name).map_err(|e| e.to_string())?;
    pw.add_otp(uuid, otp).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn list_otps(
    user: Option<String>,
    vault: Option<String>,
) -> Result<(), String> {
    let user = get_username(user)?;
    let core_password = prompt_core_password(user.clone())?;
    let config = load_config(&user, &core_password)?;
    let vault = select_vault(&config, vault)?;
    let pw = PasswordManager::new(&vault.path)
                                                .map_err(|e| e.to_string())?;
    let otp_entries = pw.list_otp().map_err(|e| e.to_string())?;
    if otp_entries.is_empty() {
        println!("No OTP entries found.");
    } else {
        println!("OTP Entries (name | note | url):");
        for entry in otp_entries.clone() {
            let uuid = entry.id;
            let passentry = pw.get_password_entry(uuid).map_err(|e| e.to_string())?;
            println!("- {} | {} | {}", 
                    passentry.name, 
                    passentry.note.unwrap_or("-".to_string()), 
                    passentry.url.unwrap_or("-".to_string()));
        }
        println!("Total: {} entries", otp_entries.len());
    }
    Ok(())
}
