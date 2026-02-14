use crate::configtool::*;
use crate::pwsmanager;
use crate::securecrypto::SecureCrypto;
use crate::securecrypto::decrypt_private_key;
use crate::passgen;
use crate::pwsmanager::PasswordPolicy;

pub fn add_password_interactive(user_arg: Option<String>, vault_arg: Option<String>) -> Result<(), String> {
    let user = get_username(user_arg)?;
    let core_password = prompt_core_password(user.clone())?;

    let config = load_config(&user, &core_password)?;
    let private_key = decrypt_private_key(&config.encrypted_private_key, &core_password)?;
    let crypto = SecureCrypto::from_pem_keys(&config.public_key, &private_key)
        .map_err(|e| format!("Failed to initialize crypto: {}", e))?;

    let vault = select_vault(&config, vault_arg)?;
    let manager = pwsmanager::PasswordManager::new(&vault.path)
        .map_err(|e| format!("Failed to open vault: {}", e))?;

    let name = prompt_input("Enter password name/label: ")?;
    let username = prompt_input("Enter username (optional): ");
    let url = prompt_input("Enter URL (optional): ");
    let note = prompt_input("Enter note (optional): ");

    let (password, policy, expiration_days) = loop {
        let choice = prompt_input("Generate password (g) or enter manually (m)? [g/m]: ")?;
        match choice.trim().to_lowercase().as_str() {
            "g" | "generate" => {
                let password_type = prompt_input("Generate random (r) or memorable (m) password? [r/m]: ")?;
                match password_type.trim().to_lowercase().as_str() {
                    "r" | "random" => {
                        let result = handle_random_password()?;
                        break result;
                    },
                    "m" | "memorable" => {
                        let result = handle_memorable_password()?;
                        break result;
                    },
                    _ => {
                        eprintln!("Invalid choice");
                        continue;
                    }
                };
            },
            "m" | "manual" => {
                let password = input_password_check()?;
                let expiration_days_input = prompt_input("Enter password expiration days (0 for no expiration, default 0): ")?;
                let expiration_days = if expiration_days_input.trim().is_empty() {
                    0
                } else {
                    expiration_days_input.parse().map_err(|_| "Invalid expiration days".to_string())?
                };
                break (password, None, expiration_days);
            },
            _ => {
                eprintln!("Invalid choice");
                continue;
            }
        }
    };

    let encrypted_bytes = crypto.encrypt_string(&password).expect("Encryption failed");

    let id = manager.add_password(
        name,
        username.ok(),
        encrypted_bytes,
        url.ok(),
        expiration_days,
        policy,
        note.ok(),
    ).map_err(|e| format!("Failed to add password: {}", e))?;

    {
        let mut vault_meta = VaultMetadata::get_vaultmetadata(&vault.path).unwrap();
        vault_meta.vault_updated();
    }

    println!("Password added with ID: {}", id);
    Ok(())
}

fn handle_random_password() -> Result<(String, Option<PasswordPolicy>, u32), String> {
    let length_input = prompt_input("Enter password length (default 16): ")?;
    let length = if length_input.trim().is_empty() {
        16
    } else {
        length_input.parse().map_err(|_| "Invalid length".to_string())?
    };
    let mut options = passgen::PasswordOptions::default();
    println!("Random password policy:");
    println!("- Length: {}", length);
    println!("- Includes uppercase: Yes");
    println!("- Includes lowercase: Yes");
    println!("- Includes numbers: Yes");
    println!("- Includes special characters: Yes");
    println!("- URL safe: No");
    println!("- Avoid confusion: No");
    let confirm_policy = prompt_input("Use this policy? [y/n]: ")?;
    options = if confirm_policy.trim().to_lowercase() != "y" {
        eprintln!("Customizing password policy...");
        let uppercase = prompt_input("Include uppercase letters? [y/n]: ")?.trim().to_lowercase() == "y";
        let lowercase = prompt_input("Include lowercase letters? [y/n]: ")?.trim().to_lowercase() == "y";
        let numbers = prompt_input("Include numbers? [y/n]: ")?.trim().to_lowercase() == "y";
        let special = prompt_input("Include special characters? [y/n]: ")?.trim().to_lowercase() == "y";
        let url_safe = prompt_input("Make URL safe? [y/n]: ")?.trim().to_lowercase() == "y";
        let avoid_confusion = prompt_input("Avoid confusing characters? [y/n]: ")?.trim().to_lowercase() == "y";
        passgen::PasswordOptions {
            length,
            include_uppercase: uppercase,
            include_lowercase: lowercase,
            include_numbers: numbers,
            include_special: special,
            url_safe,
            avoid_confusion,
        }
    } else {
        passgen::PasswordOptions {
            length,
            ..options
        }
    };
    let password = passgen::generate_password(&options)?;
    println!("Generated password: {}", password);
    
    let confirm = prompt_input("Use this password? [y/n]: ")?;
    if confirm.trim().to_lowercase() == "y" {
        let policy = pwsmanager::PasswordPolicy::Random {
            length: options.length,
            include_uppercase: options.include_uppercase,
            include_lowercase: options.include_lowercase,
            include_numbers: options.include_numbers,
            include_special: options.include_special,
            url_safe: options.url_safe,
            avoid_confusion: options.avoid_confusion,
        };
        let expiration_days_input = prompt_input("Enter password expiration days (0 for no expiration, default 0): ")?;
        let expiration_days = if expiration_days_input.trim().is_empty() {
            0
        } else {
            expiration_days_input.parse().map_err(|_| "Invalid expiration days".to_string())?
        };
        Ok((password, Some(policy), expiration_days))
    } else {
        handle_random_password()
    }
}

fn handle_memorable_password() -> Result<(String, Option<PasswordPolicy>, u32), String> {
    let words_input = prompt_input("Enter number of words (default 4): ")?;
    let words = if words_input.trim().is_empty() {
        4
    } else {
        words_input.parse().map_err(|_| "Invalid number of words".to_string())?
    };
    let mut options = passgen::MemorablePasswordOptions::default();
    println!("Memorable password policy:");
    println!("- Number of words: {}", words);
    println!("- Separator: '-'");
    println!("- Include numbers: Yes");
    println!("- Capitalization: CamelCase (first letter uppercase)");
    let confirm_policy = prompt_input("Use this policy? [y/n]: ")?;
    options = if confirm_policy.trim().to_lowercase() != "y" {
        eprintln!("Customizing memorable password policy...");
        let separator = prompt_input("Enter separator character: ")?;
        let separator = separator.trim().chars().next().unwrap_or('-');
        let include_numbers = prompt_input("Include numbers? [y/n]: ")?.trim().to_lowercase() == "y";
        let capitalization_input = prompt_input("Capitalization style (none/camel/random): ")?;
        let capitalization = match capitalization_input.trim().to_lowercase().as_str() {
            "camel" => passgen::Capitalization::CamelCase,
            "random" => passgen::Capitalization::RandomCase,
            _ => passgen::Capitalization::NoCapitalization,
        };
        passgen::MemorablePasswordOptions {
            word_count: words,
            include_numbers,
            separator,
            capitalization,
        }
    } else {
        passgen::MemorablePasswordOptions {
            word_count: words,
            ..options
        }
    };
    let password = passgen::generate_memorable_password(&options)?;
    println!("Generated password: {}", password);

    let confirm = prompt_input("Use this password? [y/n]: ")?;
    if confirm.trim().to_lowercase() == "y" {
        let policy = pwsmanager::PasswordPolicy::Memorable {
            words: options.word_count as u8,
            separator: options.separator,
            include_numbers: options.include_numbers,
            capitalization: options.capitalization,
        };
        let expiration_days_input = prompt_input("Enter password expiration days (0 for no expiration, default 0): ")?;
        let expiration_days = if expiration_days_input.trim().is_empty() {
            0
        } else {
            expiration_days_input.parse().map_err(|_| "Invalid expiration days".to_string())?
        };
        Ok((password, Some(policy), expiration_days))
    } else {
        handle_memorable_password()
    }
}
