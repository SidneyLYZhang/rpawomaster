//  ____  ____     __        __    __  __           _
// |  _ \|  _ \ __ \ \      / /__ |  \/  | __ _ ___| |_ ___ _ __ 
// | |_) | |_) / _` \ \ /\ / / _ \| |\/| |/ _` / __| __/ _ \ '__|
// |  _ <|  __/ (_| |\ V  V / (_) | |  | | (_| \__ \ ||  __/ |   
// |_| \_\_|   \__,_| \_/\_/ \___/|_|  |_|\__,_|___/\__\___|_|   
//
// Author : Sidney Zhang <zly@lyzhang.me>
// Date : 2025-07-02
// Version : 0.1.0
// License : Mulan PSL v2
//
// Secure Crypto Lib

use anyhow::{anyhow, Context, Result};
use aes::{
    cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    Aes256,
};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rand::RngCore;
use base64::{engine::general_purpose, Engine as _};
use cbc::{Decryptor, Encryptor};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::LineEnding;
use sled::IVec;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use tar::{Archive, Builder};
use tempfile::NamedTempFile;
use walkdir::WalkDir;
use rand::rngs::OsRng;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

const EXTENSION: &str = "esz";
const RSA_KEY_SIZE: usize = 2048;

pub struct SecureCrypto {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl SecureCrypto {
    /// 从PEM格式字符串创建加密模块
    pub fn from_pem_keys(public_key_pem: &str, private_key_pem: &str) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
            .context("Failed to parse private key PEM")?;
        let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
            .context("Failed to parse public key PEM")?;

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// 加密字符串，返回适合sled存储的格式
    pub fn encrypt_string(&self, text: &str) -> Result<Vec<u8>> {
        // 生成随机AES密钥和IV
        let (aes_key, iv) = self.generate_aes_components();

        // 用AES加密文本
        let ciphertext = self.aes_encrypt(text.as_bytes(), &aes_key, &iv)?;

        // 用RSA加密AES密钥
        let encrypted_key = self
            .public_key
            .encrypt(
                &mut rand::thread_rng(),
                Oaep::new::<sha2::Sha256>(),
                &aes_key,
            )
            .context("RSA encryption failed")?;

        // 组装数据包: [RSA加密的密钥长度(4B) | RSA加密的密钥 | IV(16B) | AES加密的数据]
        let mut result = Vec::with_capacity(4 + encrypted_key.len() + 16 + ciphertext.len());
        result.extend_from_slice(&(encrypted_key.len() as u32).to_le_bytes());
        result.extend_from_slice(&encrypted_key);
        result.extend_from_slice(&iv);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// 解密sled存储格式的字符串
    pub fn decrypt_string(&self, data: &IVec) -> Result<String> {
        let data = data.as_ref();

        // 解析数据包结构
        if data.len() < 4 + 16 {
            return Err(anyhow!("Invalid encrypted data format: too short ({} bytes)", data.len()));
        }

        let key_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let key_start = 4;
        let key_end = key_start + key_len;
        let iv_start = key_end;
        let iv_end = iv_start + 16;
        let ciphertext_start = iv_end;

        if data.len() < ciphertext_start {
            return Err(anyhow!("Invalid encrypted data format: key_len {} exceeds data length {} (needs at least {})", key_len, data.len(), ciphertext_start));
        }

        // 提取各部分数据
        let encrypted_key = &data[key_start..key_end];
        let iv = &data[iv_start..iv_end];
        let ciphertext = &data[ciphertext_start..];

        // 用RSA解密AES密钥
        let aes_key = self
            .private_key
            .decrypt(Oaep::new::<sha2::Sha256>(), encrypted_key)
            .context("RSA decryption failed")?;

        // 用AES解密文本
        let plaintext = self.aes_decrypt(ciphertext, &aes_key, iv)?;
        String::from_utf8(plaintext).context("Decrypted text is not valid UTF-8")
    }

    /// 加密文件或目录
    pub fn encrypt_path(&self, source_path: impl AsRef<Path>, target_path: impl AsRef<Path>) -> Result<()> {
        let source_path = source_path.as_ref();
        let target_path = target_path.as_ref();
        
        if source_path.is_dir() {
            self.encrypt_dir(source_path, target_path)
        } else {
            self.encrypt_file(source_path, target_path)
        }
    }

    /// 解密文件或目录
    pub fn decrypt_path(&self, source_path: impl AsRef<Path>, target_path: impl AsRef<Path>) -> Result<()> {
        let source_path = source_path.as_ref();
        let target_path = target_path.as_ref();
        
        if source_path.is_file() && source_path.extension().map_or(false, |e| e == "esz") {
            // 检查目标路径：如果是目录，则解压；如果是文件，则解密为文件
            if target_path.extension().is_none() || target_path.is_dir() {
                // 目标路径看起来像目录，执行目录解压
                self.decrypt_dir(source_path, target_path)
            } else {
                // 目标路径看起来像文件，执行文件解密
                self.decrypt_file(source_path, target_path)
            }
        } else {
            Err(anyhow!("Invalid source path for decryption: must be a .esz file"))
        }
    }

    // --- 私有方法 ---
    fn generate_aes_components(&self) -> (Vec<u8>, [u8; 16]) {
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];
        let mut rng = OsRng;
        let _ = rng.try_fill_bytes(&mut key);
        let _ = rng.try_fill_bytes(&mut iv);
        (key.to_vec(), iv)
    }

    fn aes_encrypt(&self, data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err(anyhow!("Invalid AES key length"));
        }
        if iv.len() != 16 {
            return Err(anyhow!("Invalid IV length"));
        }

        let cipher = Aes256CbcEnc::new(key.into(), iv.into());
        Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(data))
    }

    fn aes_decrypt(&self, data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if key.len() != 32 {
            return Err(anyhow!("Invalid AES key length"));
        }
        if iv.len() != 16 {
            return Err(anyhow!("Invalid IV length"));
        }

        let cipher = Aes256CbcDec::new(key.into(), iv.into());
        cipher
            .decrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|e| anyhow!("AES decryption failed: {:?}", e))
    }

    fn encrypt_file(&self, input_path: &Path, output_path: &Path) -> Result<()> {
        let mut input_file = fs::File::open(input_path)
            .with_context(|| format!("Failed to open input file: {:?}", input_path))?;

        let filename = input_path.file_name()          // -> Some(OsStr)
                                        .and_then(|s| s.to_str()) // -> Option<&str>
                                        .unwrap_or("");

        // 读取文件内容
        let mut data = Vec::new();
        input_file
            .read_to_end(&mut data)
            .context("Failed to read file content")?;

        // 加密内容
        let encrypted_data = self.encrypt_string(&general_purpose::STANDARD.encode(&data))?;

        // 确保输出目录存在
        if !output_path.exists() {
            fs::create_dir_all(output_path)?;
        }
        let output_file_path = output_path.join(format!("{}.{}", filename, EXTENSION));
        
        // 写入加密文件
        let mut output_file = fs::File::create(&output_file_path)
            .with_context(|| format!("Failed to create output file: {:?}", output_file_path))?;
        output_file
            .write_all(&encrypted_data)
            .context("Failed to write encrypted data")?;

        Ok(())
    }

    fn decrypt_file(&self, input_path: &Path, output_path: &Path) -> Result<()> {
        if !input_path.exists() {
            return Err(anyhow!("Input file does not exist"));
        }
        if !input_path.extension().map_or(false, |e| e == EXTENSION) {
            return Err(anyhow!("Invalid input file extension"));
        }

        let mut input_file = fs::File::open(input_path)
            .with_context(|| format!("Failed to open input file: {:?}", input_path))?;
        let filename = input_path.file_stem()          // -> Some(OsStr)
                                        .and_then(|s| s.to_str()) // -> Option<&str>
                                        .unwrap_or("");
        
        // 读取加密内容
        let mut encrypted_data = Vec::new();
        input_file
            .read_to_end(&mut encrypted_data)
            .context("Failed to read encrypted data")?;

        // 解密内容
        let decrypted_base64 = self.decrypt_string(&IVec::from(encrypted_data))?;
        let decrypted_data = general_purpose::STANDARD
            .decode(&decrypted_base64)
            .context("Failed to decode base64 data")?;

        // 确保输出目录存在
        if !output_path.exists() {
            fs::create_dir_all(output_path)?;
        }

        // 写入原始文件
        let output_file_path = output_path.join(filename);
        let mut output_file = fs::File::create(&output_file_path)
            .with_context(|| format!("Failed to create output file: {:?}", output_file_path))?;
        output_file
            .write_all(&decrypted_data)
            .context("Failed to write decrypted data")?;

        Ok(())
    }

    fn encrypt_dir(&self, dir_path: &Path, target_path: &Path) -> Result<()> {
        // 创建临时tar文件
        let temp_dir = tempfile::tempdir()?;
        let temp_tar_path = temp_dir.path().join("temp.tar");
        
        // 创建tar归档
        self.create_tar_archive(dir_path, &temp_tar_path)?;
        
        // 加密tar文件到指定目标位置
        self.encrypt_file(&temp_tar_path, target_path)?;
        
        // 临时目录自动清理
        Ok(())
    }

    fn decrypt_dir(&self, input_path: &Path, output_dir: &Path) -> Result<()> {
        // 创建临时目录用于解包
        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir.path();
        
        // 解密tar文件到临时目录
        let decrypted_tar_path = temp_path.join("decrypted.tar");
        self.decrypt_file_to(input_path, &decrypted_tar_path)?;
        
        // 确保输出目录不存在或为空
        if output_dir.exists() {
            fs::remove_dir_all(output_dir)?;
        }
        
        // 创建输出目录的父目录
        if let Some(parent) = output_dir.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // 解包tar文件到指定输出目录
        self.extract_tar_archive(&decrypted_tar_path, output_dir)?;
        
        // 临时目录自动删除
        Ok(())
    }

    fn decrypt_file_to(&self, input_path: &Path, output_path: &Path) -> Result<()> {
        let mut input_file = fs::File::open(input_path)
            .with_context(|| format!("Failed to open input file: {:?}", input_path))?;

        // 读取加密内容
        let mut encrypted_data = Vec::new();
        input_file
            .read_to_end(&mut encrypted_data)
            .context("Failed to read encrypted data")?;

        // 解密内容
        let decrypted_base64 = self.decrypt_string(&IVec::from(encrypted_data))?;
        let decrypted_data = general_purpose::STANDARD
            .decode(&decrypted_base64)
            .context("Failed to decode base64 data")?;

        // 确保输出目录存在
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // 写入文件
        let mut output_file = fs::File::create(output_path)
            .with_context(|| format!("Failed to create output file: {:?}", output_path))?;
        output_file
            .write_all(&decrypted_data)
            .context("Failed to write decrypted data")?;

        Ok(())
    }

    fn create_tar_archive(&self, source_dir: &Path, tar_path: &Path) -> Result<()> {
        let tar_file = File::create(tar_path)?;
        let mut tar_builder = Builder::new(tar_file);
        
        // 显式添加所有文件和子目录以确保目录结构完整
        for entry in WalkDir::new(source_dir) {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                let relative_path = path.strip_prefix(source_dir)?;
                tar_builder.append_path_with_name(path, relative_path)?;
            } else if path.is_dir() && path != source_dir {
                let relative_path = path.strip_prefix(source_dir)?;
                let mut header = tar::Header::new_gnu();
                header.set_mode(0o755);
                header.set_size(0);
                header.set_cksum();
                tar_builder.append_data(&mut header, relative_path, std::io::empty())?;
            }
        }
        
        tar_builder.finish()?;
        Ok(())
    }

    fn extract_tar_archive(&self, tar_path: &Path, output_dir: &Path) -> Result<()> {
        let tar_file = File::open(tar_path)?;
        let mut archive = Archive::new(tar_file);
        archive.unpack(output_dir)?;
        Ok(())
    }

    fn copy_dir_recursive(&self, src: &Path, dst: &Path) -> Result<()> {
        if !dst.exists() {
            fs::create_dir_all(dst)?;
        }
        
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());
            
            if entry.file_type()?.is_dir() {
                self.copy_dir_recursive(&src_path, &dst_path)?;
            } else {
                fs::copy(&src_path, &dst_path)?;
            }
        }
        Ok(())
    }


}

// 密钥生成工具函数
// pub fn generate_keys() -> Result<(String, String)> {
//     let mut rng = rand::thread_rng();
//     let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_SIZE)
//         .context("Failed to generate RSA key pair")?;
//     let public_key = RsaPublicKey::from(&private_key);

//     let private_pem = private_key
//         .to_pkcs8_pem(LineEnding::LF)
//         .context("Failed to serialize private key")?
//         .to_string();
//     let public_pem = public_key
//         .to_public_key_pem(LineEnding::LF)
//         .context("Failed to serialize public key")?;
//     Ok((public_pem, private_pem))
// }
pub fn generate_rsa_keypair() -> Result<(String, String), String> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_SIZE)
        .map_err(|e| format!("Failed to generate RSA key pair: {}", e))?;
    let public_key = private_key.to_public_key();

    let private_key_pem = private_key.to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("Failed to serialize private key: {}", e))?;
    let public_key_pem = public_key.to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("Failed to serialize public key: {}", e))?;

    Ok((private_key_pem.to_string(), public_key_pem.to_string()))
}


#[cfg(test)]
mod tests {
    use super::*;
    use sled::IVec;
    use tempfile::{NamedTempFile, tempdir};
    use std::fs;
    use std::io::Write;


    #[test]
    fn test_encrypt_decrypt_string() {
        // 生成密钥对
        let (private_pem, public_pem) = generate_rsa_keypair().expect("Failed to generate RSA key pair");
        
        // 创建SecureCrypto实例
        let crypto = SecureCrypto::from_pem_keys(&public_pem, &private_pem).expect("Failed to create SecureCrypto instance");
        
        // 测试字符串
        let test_str = "Hello, World! This is a test string with special characters: )V?(3S8}5mrM?%XW".to_string();
        
        // 加密字符串
        let encrypted_data = crypto.encrypt_string(&test_str).expect("Encryption failed");
        
        // 解密字符串
        let decrypted_str = crypto.decrypt_string(&IVec::from(encrypted_data)).expect("Decryption failed");
        
        // 验证解密结果
        assert_eq!(decrypted_str, test_str, "Decrypted string does not match original");
    }

    #[test]
    fn test_encrypt_decrypt_empty_string() {
        // 生成密钥对
        let (private_pem, public_pem) = generate_rsa_keypair().expect("Failed to generate RSA key pair");
        
        // 创建SecureCrypto实例
        let crypto = SecureCrypto::from_pem_keys(&public_pem, &private_pem).expect("Failed to create SecureCrypto instance");
        
        // 测试空字符串
        let test_str = "";
        
        // 加密字符串
        let encrypted_data = crypto.encrypt_string(test_str).expect("Encryption failed");
        
        // 解密字符串
        let decrypted_str = crypto.decrypt_string(&IVec::from(encrypted_data)).expect("Decryption failed");
        
        // 验证解密结果
        assert_eq!(decrypted_str, test_str, "Decrypted empty string does not match original");
    }

    #[test]
    fn test_encrypt_decrypt_file() {
        // 生成密钥对
        let (private_pem, public_pem) = generate_rsa_keypair().expect("Failed to generate RSA key pair");
        let crypto = SecureCrypto::from_pem_keys(&public_pem, &private_pem).expect("Failed to create SecureCrypto instance");

        // 创建临时测试文件
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let temp_file_path = temp_dir.path().join("test_file.txt");
        let test_content = b"Test file content with special characters: \xE6\xB5\x8B\xE8\xAF\x95\xE6\x96\x87\xE6\x9C\xAC \xC2\xA3\xC2\xA5\xE2\x82\xAC";
        fs::write(&temp_file_path, test_content).expect("Failed to write to temp file");
        let filename = "test_file.txt";

        // 创建加密文件的目标路径
        let encrypted_path = temp_file_path.parent().unwrap();
        let encrypted_file_path = encrypted_path.join(format!("{}.esz", filename));

        // 加密文件
        crypto.encrypt_file(&temp_file_path, &encrypted_path).expect("File encryption failed");

        // 验证加密文件存在
        assert!(encrypted_file_path.exists(), "Encrypted file not created");

        // 删除原始文件以确保解密效果
        fs::remove_file(&temp_file_path).expect("Failed to remove original file");

        // 创建解密文件的目标路径
        let decrypted_path = temp_dir.path();
        let decrypted_file_path = decrypted_path.join(filename);
        
        // 解密文件
        crypto.decrypt_file(&encrypted_file_path, &decrypted_path).expect("File decryption failed");

        // 验证解密文件存在且内容正确
        assert!(decrypted_file_path.exists(), "Decrypted file not created");
        let decrypted_content = fs::read(&decrypted_file_path).expect("Failed to read decrypted file");
        assert_eq!(decrypted_content, test_content, "Decrypted file content does not match original");
    }

    #[test]
    fn test_encrypt_decrypt_directory() {
        // 生成密钥对
        let (private_pem, public_pem) = generate_rsa_keypair().expect("Failed to generate RSA key pair");
        let crypto = SecureCrypto::from_pem_keys(&public_pem, &private_pem).expect("Failed to create SecureCrypto instance");

        // 创建临时目录
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let temp_dir_path = temp_dir.path();

        // 创建测试目录结构
        let test_dir = temp_dir_path.join("test_dir");
        fs::create_dir(&test_dir).expect("Failed to create test directory");

        // 创建子目录
        let subdir = test_dir.join("subdir");
        fs::create_dir(&subdir).expect("Failed to create subdirectory");

        // 创建文件1
        let file1 = test_dir.join("file1.txt");
        fs::write(&file1, b"Content of file 1").expect("Failed to write file1");

        // 创建文件2
        let file2 = subdir.join("file2.txt");
        fs::write(&file2, b"Content of file 2 with special characters: \xE6\xB5\x8B\xE8\xAF\x95\xE7\x9B\xAE\xE5\xBD\x95\xE5\x8A\xA0\xE5\xAF\x86").expect("Failed to write file2");

        // 创建加密文件的目标路径
        let filename = test_dir.file_name().unwrap().to_str().unwrap();
        let encrypted_path = temp_dir_path.join(format!("{}.esz", filename));

        // 加密目录
        crypto.encrypt_path(&test_dir, &encrypted_path).expect("Directory encryption failed");

        // 验证加密文件存在
        assert!(encrypted_path.exists(), "Encrypted directory file not created");

        // 删除原始目录以确保解密效果
        fs::remove_dir_all(&test_dir).expect("Failed to remove original directory");

        // 创建解密目录的目标路径
        let decrypted_dir = temp_dir_path.join("decrypted_test_dir");

        // 解密目录
        crypto.decrypt_path(&encrypted_path, &decrypted_dir).expect("Directory decryption failed");

        // 验证解密后的目录结构和内容
        assert!(decrypted_dir.exists(), "Decrypted directory not created");
        let decrypted_subdir = decrypted_dir.join("subdir");
        assert!(decrypted_subdir.exists(), "Decrypted subdirectory not found");
        let decrypted_file1 = decrypted_dir.join("file1.txt");
        let decrypted_file2 = decrypted_subdir.join("file2.txt");
        assert!(decrypted_file1.exists(), "Decrypted file1 not found");
        assert!(decrypted_file2.exists(), "Decrypted file2 not found");

        // 验证文件内容
        assert_eq!(fs::read(&decrypted_file1).expect("Failed to read decrypted file1"), b"Content of file 1");
        assert_eq!(fs::read(&decrypted_file2).expect("Failed to read decrypted file2"), b"Content of file 2 with special characters: \xE6\xB5\x8B\xE8\xAF\x95\xE7\x9B\xAE\xE5\xBD\x95\xE5\x8A\xA0\xE5\xAF\x86");
    }
}