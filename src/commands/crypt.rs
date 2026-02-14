use crate::configtool::*;
use crate::securecrypto::{SecureCrypto, generate_rsa_keypair, save_keypair, read_keypair};
use crate::securecrypto::{encrypt_private_key, decrypt_private_key};
use std::path::PathBuf;
use tempfile::tempdir;

pub fn encrypt_path(
    password: Option<String>,
    source: String,
    target: String,
) -> Result<(), String> {
    let (private_key, public_key) = generate_rsa_keypair()?;

    let password = match password {
        Some(p) => p,
        None => {
            let password = read_password_from_stdin("Enter password: ")?;
            let confirm = read_password_from_stdin("Confirm password: ")?;
            if password != confirm {
                return Err("Passwords do not match".to_string());
            }
            password
        }
    };

    let encrypted_private_key = encrypt_private_key(&private_key, &password)?;

    let secure_crypto = SecureCrypto::from_pem_keys(&public_key,&private_key)
        .map_err(|e| format!("Failed to initialize crypto: {}", e))?;

    let temp_path = tempdir().map_err(|e| format!("Failed to create temp dir: {}", e))?;
    let encrypted_dir = temp_path.path();
    save_keypair(encrypted_private_key, public_key, encrypted_dir)?;
    secure_crypto.encrypt_path(&source, &encrypted_dir)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    let dst = PathBuf::from(target.clone());
    let src = PathBuf::from(source.clone());
    let dst_path = dst.join(format!("{}.esz",src.file_name().unwrap().to_string_lossy()));
    secure_crypto.create_tar_archive(encrypted_dir, &dst_path)
                .map_err(|e| format!("Failed to create tar archive: {}", e))?;
    println!("Successfully encrypted '{}' to '{}'", source, target);
    Ok(())
}

pub fn decrypt_path(
    password: Option<String>,
    source: String,
    target: String,
) -> Result<(), String> {
    let password = match password {
        Some(p) => p,
        None => read_password_from_stdin("Enter password: ")?,
    };

    let temp_path = tempdir().map_err(|e| format!("Failed to create temp dir: {}", e))?;
    let encrypted_dir = temp_path.path();
    let src = PathBuf::from(source.clone());
    {
        let (private_key, public_key) = generate_rsa_keypair()?;
        let secure_crypto = SecureCrypto::from_pem_keys(&public_key,&private_key)
                                            .map_err(|e| format!("Failed to initialize crypto: {}", e))?;
        secure_crypto.extract_tar_archive(&src, encrypted_dir)
                        .map_err(|e| format!("Failed to extract tar archive: {}", e))?;
    }
    let (encrypted_private_key, public_key) = read_keypair(encrypted_dir)?;

    let private_key = decrypt_private_key(&encrypted_private_key, &password)?;

    let secure_crypto = SecureCrypto::from_pem_keys(&public_key,&private_key)
        .map_err(|e| format!("Failed to initialize crypto: {}", e))?;

    let src_path = encrypted_dir.join(format!("{}.esz", src.file_stem().unwrap().to_string_lossy()));
    secure_crypto.decrypt_path(&src_path, &target)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    println!("Successfully decrypted '{}' to '{}'", source, target);
    Ok(())
}
