use crate::configtool::*;
use crate::pwsmanager;

pub fn delete_password(
    passwordname: String,
    user: Option<String>,
    vault: Option<String>,
) -> Result<(), String> {
    let username = get_username(user)?;
    let _ = prompt_core_password(username.clone())?;
    let mut config = load_user_config(&username)?;
    let mut vault = select_vault(&config, vault)?;

    let pm = pwsmanager::PasswordManager::new(&vault.path)
                                    .map_err(|e| format!("Failed to initialize password manager: {}", e))?;
    pm.delete_password(None, Some(passwordname.clone()))
        .map_err(|e| format!("Failed to delete password: {}", e))?;
    
    vault.update_vault();
    config.update_vault(vault);
    println!("Password {} deleted successfully.", passwordname);
    Ok(())
}
