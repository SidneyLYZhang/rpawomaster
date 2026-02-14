use crate::configtool::*;
use crate::passgen;
use crate::securecrypto::decrypt_private_key;

pub fn interactive_init(user: Option<String>) -> Result<(), String> {
    let username = match user {
        Some(u) => u,
        None => loop {
                let user_name = prompt_input("Enter username: ")?;
                if user_name.is_empty() {
                    println!("Username cannot be empty. Please try again.");
                    continue;
                }
                break user_name;
        },
    };

    let existing_user = check_user_exist(&username)?;
    let core_password = if existing_user {
        let password = read_password_from_stdin("Enter core password to authenticate: ")?;
        let mut config: ConfigFile = load_config(&username, &password)?;
        config.check_corepassword_valid(&password)?;
        decrypt_private_key(&config.encrypted_private_key, &password)
            .map_err(|e| format!("Authentication failed: {}", e))?;
        password
    } else {
        let mut password;
        loop {
            password = read_password_from_stdin("Enter core password: ")?;
            let confirm = read_password_from_stdin("Confirm core password: ")?;
            if password != confirm {
                println!("Passwords do not match. Please try again.");
                continue;
            }
            let (rating, score, feedback) = passgen::assess_password_strength(&password)?;
            if score < 3 {
                println!("Warning: Weak core password. {}", feedback);
                println!("New Core Password is {} ({}/4).", rating, score);
                let response = prompt_input("Continue with this weak password? [y/N]: ")?;
                if !response.trim().eq_ignore_ascii_case("y") {
                    break;
                } else {
                    continue;
                }
            } else {
                println!("⭐ 核心密码强度 {} ({}/4).\n", rating, score);
            }
            break;
        }
        password
    };

    let vault_name = prompt_input("Enter vault name (default: MyVault): ")?;
    let vault_name = if vault_name.is_empty() { "MyVault".to_string() } else { vault_name };

    let vault_path = prompt_input(
        format!("Enter vault save location (default: {{config path}}/vaults/{}): ", vault_name.clone()).as_str())?;
    let default_vault_path = get_config_dir()?
        .join("vaults")
        .join(vault_name.clone());
    let vault_path = if vault_path.is_empty() {
        default_vault_path.to_string_lossy().into_owned()
    } else {
        vault_path.to_string()
    };

    let vault_path_buf = std::path::PathBuf::from(&vault_path);
    std::fs::create_dir_all(&vault_path_buf)
        .map_err(|e| format!("Failed to create vault directory: {}", e))?;
    
    let mut new_vault = Vault::new(&vault_name, &vault_path, Some(false));
    let mut config = load_config(&username, &core_password)?;

    if existing_user {
        config.check_corepassword_valid(&core_password)?;
        let mut default_vault_number = 0;
        println!("\nExisting vaults:");
        for (i, vault) in config.vaults.iter().enumerate() {
            if vault.is_default {
                default_vault_number = i + 1;
            }
            println!("{}. {} (Path: {}, Default: {})", 
                     i + 1, 
                     vault.name, 
                     vault.path, 
                     if vault.is_default { "Yes" } else { "No" });
        }
        println!("{}. {} (new vault)", config.vaults.len() + 1, new_vault.name);

        let selection: usize = loop {
            let response = prompt_input("\nEnter the number of the vault to set as default: ")?;
            let selection: usize = if response.is_empty() {
                default_vault_number
            } else {
                response.parse()
                        .map_err(|_| "Invalid selection. Please enter a number.".to_string())?
            };
            if selection < 1 || selection > config.vaults.len() + 1 {
                println!("Invalid selection. Please enter a number between 1 and {}.", config.vaults.len() + 1);
                continue;
            }
            break selection;
        };

        if selection != default_vault_number {
            for vault in &mut config.vaults {
                vault.is_default = false;
            }

            if selection <= config.vaults.len() {
                config.vaults[selection - 1].is_default = true;
            } else {
                new_vault.is_default = true;
            }
        }
        config.add_vault(new_vault.clone());
    } else {
        new_vault.set_default(true);
        config.add_vault(new_vault.clone());
    }

    let _ = config.save_config();

    let metadata = VaultMetadata::from_vault(&new_vault);
    let _ = metadata.save_vaultmetadata();

    Ok(())
}
