use crate::configtool::*;
use crate::pwsmanager::PasswordManager;
use crate::securecrypto::SecureCrypto;
use crate::securecrypto::decrypt_private_key;
use crate::xotp::{XOTP, XOTPType, generate_code};
use sled::IVec;

pub fn search_passwords(
    text: String,
    user: Option<String>,
    vault: Option<String>,
    exact: Option<bool>,
) -> Result<(), String> {
    let username = get_username(user)?;
    let core_password = prompt_core_password(username.clone())?;
    let config: ConfigFile = load_config(&username, &core_password)?;
    let target_vault = select_vault(&config, vault)?;
    let private_key_pem = decrypt_private_key(&config.encrypted_private_key, &core_password)?;
    let crypto = SecureCrypto::from_pem_keys(&config.public_key, &private_key_pem)
        .map_err(|e| format!("Failed to initialize crypto: {}", e))?;
    let exact_match = exact.unwrap_or(false);
    let pm = PasswordManager::new(&target_vault.path)
        .map_err(|e| format!("Failed to open vault: {}", e))?;
    let entries = pm.find_passwords(&text, exact_match)
        .map_err(|e| format!("Search failed: {}", e))?;

    if entries.is_empty() {
        println!("No passwords found matching '{}'", text);
        return Ok(());
    }

    let entry_count = entries.len();
    let selected_entry = if entry_count > 1 {
        println!("\nFound {} matching passwords:", entry_count.clone());
        for (i, entry) in entries.iter().enumerate() {
            println!("{}. Name: {}", i + 1, entry.name);
            if let Some(username) = &entry.username {
                println!("   Username: {}", username);
            }
            if let Some(url) = &entry.url {
                println!("   URL: {}", url);
            }
            if let Some(note) = &entry.note {
                println!("   Note: {}", note);
            }
            println!();
        }

        let selection = prompt_input("Enter the number of the password to view: ")?;
        let selection: usize = selection.trim().parse()
            .map_err(|_| "Invalid selection. Please enter a number.".to_string())?;
        if selection < 1 || selection > entry_count {
            return Err(format!("Invalid selection. Please enter a number between 1 and {}", entry_count));
        }
        &entries[selection - 1]
    } else {
        &entries[0]
    };

    let encrypted_bytes = selected_entry.current_password.clone();
    let decrypted_password = crypto.decrypt_string(&IVec::from(encrypted_bytes.clone()))
                                            .map_err(|e| format!("Decryption failed: {}", e))?;

    println!("\n--- Password Details ---");
    if let Some(username) = &selected_entry.username {
        println!("Username: {}", username);
    }
    if let Some(url) = &selected_entry.url {
        println!("URL: {}", url);
    }
    println!("Password: {}", decrypted_password.clone());
    if let Some((otpinfo, optcode)) = get_otp_code(&target_vault, &selected_entry.id) {
        println!("OTP Code: {}", optcode);
        match &otpinfo.otptype {
            XOTPType::TOTP => {
                let lesstime = otpinfo.get_remaining_seconds().unwrap();
                println!("Time Left: {} seconds", lesstime);
            }
            XOTPType::HOTP => {
                println!("");
            }
        }
    }
    println!("------------------------");

    Ok(())
}

fn get_otp_code(vault: &Vault, id: &uuid::Uuid) -> Option<(XOTP, String)> {
    let vault_meta = VaultMetadata::get_vaultmetadata(&vault.path).ok()?;
    let (private_key, public_key) = get_opt_password(&vault_meta).ok()?;
    let password_manager = PasswordManager::new(&vault.path).ok()?;
    let otp_config = password_manager.get_otp(*id).ok()?;
    if otp_config.is_none() {
        return None;
    }
    let mut otp_info = otp_config.unwrap();
    let crypto = SecureCrypto::from_pem_keys(&public_key, &private_key).ok()?;
    let code = generate_code(&mut otp_info, &crypto);
    Some((otp_info.clone(), code))
}
