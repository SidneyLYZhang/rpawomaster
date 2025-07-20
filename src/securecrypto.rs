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
use flate2::{write::GzEncoder, Compression};
use flate2::read::GzDecoder;
use tempfile::tempdir;
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
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let temp_tar_path = temp_dir.path().join("temp.tgz");
        
        // 创建tar归档
        self.create_tar_archive(dir_path, &temp_tar_path)?;
        
        // 加密tar文件到指定目标位置
        self.encrypt_file(&temp_tar_path, target_path)?;
        temp_dir.close()?;
        
        // 临时目录自动清理
        Ok(())
    }

    fn decrypt_dir(&self, input_path: &Path, output_dir: &Path) -> Result<()> {
        // 创建临时目录用于解包
        let temp_dir = tempdir().expect("Failed to create temp directory");
        
        // 解密tar文件到临时目录
        let decrypted_tar_path = temp_dir.path();
        self.decrypt_file(input_path, &decrypted_tar_path)?;
        
        // 确保输出目录存在
        if !output_dir.exists() {
            fs::create_dir_all(output_dir)?;
        }
        
        // 解包tar文件到指定输出目录
        self.extract_tar_archive(&decrypted_tar_path, output_dir)?;
        
        // 临时目录自动删除
        temp_dir.close()?;
        Ok(())
    }

    fn create_tar_archive(&self, source_dir: &Path, tar_path: &Path) -> Result<()> {
        // 把 `src_dir` 整个目录打包成 `dst_file`。
        // 如果 `dst_file` 以 `.gz` / `.tgz` 结尾，就自动用 gzip 压缩。
        // 创建输出文件
        let out_file = File::create(tar_path)?;

        // 根据扩展名决定是否压缩
        let extension = tar_path.extension().and_then(|e| e.to_str());
        let use_gzip = matches!(extension, Some("gz") | Some("tgz"));

        // 如果压缩就用 GzEncoder 包装，否则直接写裸 tar
        let mut tar_builder = if use_gzip {
            let enc = GzEncoder::new(out_file, Compression::default());
            Builder::new(Box::new(enc) as Box<dyn Write>)
        } else {
            Builder::new(Box::new(out_file) as Box<dyn Write>)
        };

        // 遍历目录
        for entry in WalkDir::new(source_dir) {
            let entry = entry?;
            let file_path = entry.path();
            
            // 跳过源目录本身
            if file_path == source_dir {
                continue;
            }
            
            let relative_path = file_path.strip_prefix(source_dir)
                .unwrap_or_else(|_| file_path.file_name().unwrap().as_ref());

            if file_path.is_file() {
                // 把单个文件追加进 tar
                let mut file = File::open(file_path)?;
                tar_builder.append_file(relative_path, &mut file)?;
            } else if file_path.is_dir() {
                // 空目录也需要显式追加，否则不会出现在归档里
                // 只有当目录为空时才需要显式添加
                let mut entries = fs::read_dir(file_path)?;
                if entries.next().is_none() {
                    tar_builder.append_dir(relative_path, file_path)?;
                }
            }
        }

        // Builder 会在 drop 时 flush , 手动 finish
        tar_builder.finish()?;
        Ok(())
    }

    fn extract_tar_archive(&self, tar_path: &Path, output_dir: &Path) -> Result<()> {
        // 创建或清空输出目录
        if !output_dir.exists() {
            fs::create_dir_all(output_dir)?;
        }

        // 根据扩展名决定是否用 gzip 解码
        let extension = tar_path.extension().and_then(|e| e.to_str());
        let use_gzip = matches!(extension, Some("gz") | Some("tgz"));

        let file = File::open(tar_path)?;
        let mut archive = if use_gzip {
            let dec = GzDecoder::new(file);
            Archive::new(Box::new(dec) as Box<dyn Read>)
        } else {
            Archive::new(Box::new(file) as Box<dyn Read>)
        };

        // 解包全部条目
        archive.unpack(output_dir)?;
        Ok(())
    }
}

/// 生成RSA密钥对
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
    use tempfile::tempdir;
    use std::fs;


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

        // 创建复杂测试目录结构
        let test_dir = temp_dir_path.join("complex_test_dir");
        fs::create_dir(&test_dir).expect("Failed to create test directory");

        // 创建多级嵌套目录
        let nested_dir = test_dir.join("level1").join("level2").join("level3");
        fs::create_dir_all(&nested_dir).expect("Failed to create nested directories");

        // 创建空目录
        let empty_dir = test_dir.join("empty_dir");
        fs::create_dir(&empty_dir).expect("Failed to create empty directory");

        // 创建特殊字符目录名
        let special_dir = test_dir.join("目录_файл_日本語");
        fs::create_dir(&special_dir).expect("Failed to create special directory");

        // 创建各种测试文件
        let test_files = vec![
            // 普通文本文件
            (test_dir.join("readme.txt"), b"This is a readme file with basic content.".to_vec()),
            // 空文件
            (test_dir.join("empty.txt"), b"".to_vec()),
            // 大文件 (10KB)
            (test_dir.join("large.txt"), vec![b'A'; 10240]),
            // 二进制文件
            (test_dir.join("binary.bin"), vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD]),
            // 特殊字符内容
            (test_dir.join("unicode.txt"), "测试文件内容 🚀 特殊字符: áéíóú 中文 🎉".as_bytes().to_vec()),
            // 隐藏文件
            (test_dir.join(".hidden"), b"Hidden file content".to_vec()),
            // 多级嵌套文件
            (nested_dir.join("deep.txt"), b"This file is deeply nested".to_vec()),
            // 特殊目录中的文件
            (special_dir.join("特殊文件.txt"), "特殊目录中的文件内容".as_bytes().to_vec()),
            // 长文件名
            (test_dir.join("very_long_filename_that_exceeds_normal_length_limits.txt"), b"File with very long name".to_vec()),
        ];

        // 创建所有测试文件
        for (file_path, content) in &test_files {
            fs::create_dir_all(file_path.parent().unwrap()).expect("Failed to create parent directories");
            fs::write(file_path, content).expect("Failed to write test file");
        }

        // 记录原始文件信息用于验证
        let mut original_files = Vec::new();
        for entry in WalkDir::new(&test_dir) {
            let entry = entry.expect("Failed to walk directory");
            if entry.file_type().is_file() {
                let content = fs::read(entry.path()).expect("Failed to read file");
                original_files.push((
                    entry.path().strip_prefix(&test_dir).unwrap().to_path_buf(),
                    content,
                ));
            }
        }

        // 创建加密文件的目标路径
        let filename = test_dir.file_name().unwrap().to_str().unwrap();
        let encrypted_path = temp_dir_path.join(format!("{}.esz", filename));

        // 测试目录加密
        crypto.encrypt_path(&test_dir, &encrypted_path).expect("Directory encryption failed");
        assert!(encrypted_path.exists(), "Encrypted directory file not created");
        assert!(encrypted_path.metadata().unwrap().len() > 0, "Encrypted file is empty");

        // 验证原始目录存在
        assert!(test_dir.exists(), "Original directory should still exist");

        // 创建解密目录的目标路径
        let decrypted_dir = temp_dir_path.join("decrypted_complex_dir");

        // 测试目录解密
        crypto.decrypt_path(&encrypted_path, &decrypted_dir).expect("Directory decryption failed");
        assert!(decrypted_dir.exists(), "Decrypted directory not created");

        // 验证目录结构完整性
        for (relative_path, original_content) in &original_files {
            let decrypted_path = decrypted_dir.join(relative_path);
            assert!(decrypted_path.exists(), "File not found: {:?}", relative_path);
            
            let decrypted_content = fs::read(&decrypted_path).expect("Failed to read decrypted file");
            assert_eq!(&decrypted_content, original_content, "Content mismatch for file: {:?}", relative_path);
        }

        // 验证目录结构完整性
        let mut decrypted_files = Vec::new();
        for entry in WalkDir::new(&decrypted_dir) {
            let entry = entry.expect("Failed to walk decrypted directory");
            if entry.file_type().is_file() {
                decrypted_files.push(entry.path().strip_prefix(&decrypted_dir).unwrap().to_path_buf());
            }
        }

        assert_eq!(decrypted_files.len(), original_files.len(), "File count mismatch");

        // 测试空目录加密解密
        let empty_test_dir = temp_dir_path.join("empty_test_dir");
        fs::create_dir(&empty_test_dir).expect("Failed to create empty test directory");
        
        let empty_encrypted_path = temp_dir_path.join("empty.esz");
        crypto.encrypt_path(&empty_test_dir, &empty_encrypted_path).expect("Empty directory encryption failed");
        assert!(empty_encrypted_path.exists(), "Empty directory encryption failed");

        let empty_decrypted_dir = temp_dir_path.join("decrypted_empty_dir");
        crypto.decrypt_path(&empty_encrypted_path, &empty_decrypted_dir).expect("Empty directory decryption failed");
        assert!(empty_decrypted_dir.exists(), "Empty directory decryption failed");
        assert!(empty_decrypted_dir.read_dir().unwrap().next().is_none(), "Decrypted empty directory should be empty");

        // 测试单文件加密（应该保持为文件而非目录）
        let single_file = temp_dir_path.join("single.txt");
        fs::write(&single_file, b"Single file content").expect("Failed to create single file");
        
        let single_encrypted_path = temp_dir_path.join("single.esz");
        crypto.encrypt_path(&single_file, &single_encrypted_path).expect("Single file encryption failed");
        
        let single_decrypted_path = temp_dir_path.join("decrypted_single.txt");
        crypto.decrypt_path(&single_encrypted_path, &single_decrypted_path).expect("Single file decryption failed");
        
        assert!(single_decrypted_path.is_file(), "Single file should decrypt to file");
        assert_eq!(fs::read(&single_decrypted_path).unwrap(), b"Single file content");
    }
}