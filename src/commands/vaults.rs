use crate::configtool::*;

pub fn list_vaults(user: Option<String>) -> Result<(), String> {
    let username = get_username(user)?;
    let config = load_user_config(&username)?;

    println!("\nPassword vaults for user '{}':", username);
    println!("{:<20} | {:<50} | {:<10}", "Name", "Path", "Default");
    println!("{}", "-".repeat(85));
    for vault in config.vaults {
        let default_mark = if vault.is_default { "✓" } else { "" };
        println!("{:<20} | {:<50} | {:<10}", vault.name, vault.path, default_mark);
    }
    Ok(())
}
