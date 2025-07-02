//  ____  ____     __        __    __  __           _
// |  _ \|  _ \ __ \ \      / /__ |  \/  | __ _ ___| |_ ___ _ __ 
// | |_) | |_) / _` \ \ /\ / / _ \| |\/| |/ _` / __| __/ _ \ '__|
// |  _ <|  __/ (_| |\ V  V / (_) | |  | | (_| \__ \ ||  __/ |   
// |_| \_\_|   \__,_| \_/\_/ \___/|_|  |_|\__,_|___/\__\___|_|   
//
// Auther : Sidney Zhang <zly@lyzhang.me>
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
use rsa::{Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::LineEnding;
use sled::IVec;
use std::{
    fs::{self, File},
    io::{self, Read, Write},
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
            return Err(anyhow!("Invalid encrypted data format"));
        }

        let key_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let key_start = 4;
        let key_end = key_start + key_len;
        let iv_start = key_end;
        let iv_end = iv_start + 16;
        let ciphertext_start = iv_end;

        if data.len() < ciphertext_start {
            return Err(anyhow!("Invalid encrypted data format"));
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
    pub fn encrypt_path(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if path.is_dir() {
            self.encrypt_dir(path)
        } else {
            self.encrypt_file(path)
        }
    }

    /// 解密文件或目录
    pub fn decrypt_path(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if path.is_dir() {
            self.decrypt_dir(path)
        } else {
            self.decrypt_file(path)
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

    fn encrypt_file(&self, input_path: &Path) -> Result<()> {
        let output_path = self.output_path(input_path, true)?;
        let mut input_file = fs::File::open(input_path)
            .with_context(|| format!("Failed to open input file: {:?}", input_path))?;

        // 读取文件内容
        let mut data = Vec::new();
        input_file
            .read_to_end(&mut data)
            .context("Failed to read file content")?;

        // 加密内容
        let encrypted_data = self.encrypt_string(&general_purpose::STANDARD.encode(&data))?;

        // 写入加密文件
        let mut output_file = fs::File::create(&output_path)
            .with_context(|| format!("Failed to create output file: {:?}", output_path))?;
        output_file
            .write_all(&encrypted_data)
            .context("Failed to write encrypted data")?;

        Ok(())
    }

    fn decrypt_file(&self, input_path: &Path) -> Result<()> {
        let output_path = self.output_path(input_path, false)?;
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

        // 写入原始文件
        let mut output_file = fs::File::create(&output_path)
            .with_context(|| format!("Failed to create output file: {:?}", output_path))?;
        output_file
            .write_all(&decrypted_data)
            .context("Failed to write decrypted data")?;

        Ok(())
    }

    fn encrypt_dir(&self, dir_path: &Path) -> Result<()> {
        // 创建临时tar文件
        let tar_tempfile = NamedTempFile::new()?;
        let tar_path = tar_tempfile.path();
        
        // 将文件夹打包为tar
        self.create_tar_archive(dir_path, tar_path)?;
        
        // 加密tar文件
        self.encrypt_file(tar_path)?;
        
        // 获取加密后的文件路径 (.esz)
        let encrypted_path = self.output_path(tar_path, true)?;
        
        // 重命名加密文件到目标位置
        let target_path = dir_path.with_extension(EXTENSION);
        fs::rename(encrypted_path, &target_path)?;
        
        // 临时文件自动删除
        Ok(())
    }

    fn decrypt_dir(&self, input_path: &Path) -> Result<()> {
        // 创建临时目录用于解包
        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir.path();
        
        // 解密tar文件到临时目录
        let decrypted_tar_path = temp_path.join("decrypted.tar");
        self.decrypt_file_to(input_path, &decrypted_tar_path)?;
        
        // 解包tar文件
        self.extract_tar_archive(&decrypted_tar_path, temp_path)?;
        
        // 确定目标输出目录
        let output_dir = self.output_path(input_path, false)?;
        
        // 确保输出目录不存在或为空
        if output_dir.exists() {
            fs::remove_dir_all(&output_dir)?;
        }
        
        // 重命名临时目录到目标位置
        let decrypted_dir = temp_path.read_dir()?
            .next()
            .ok_or(anyhow!("No directory in temp folder"))??
            .path();
        
        fs::rename(decrypted_dir, output_dir)?;
        
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
        
        for entry in WalkDir::new(source_dir) {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                let relative_path = path.strip_prefix(source_dir)?;
                tar_builder.append_path_with_name(path, relative_path)?;
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

    fn output_path(&self, path: &Path, encrypt: bool) -> Result<PathBuf> {
        if encrypt {
            if path.extension().map_or(false, |e| e == EXTENSION) {
                return Err(anyhow!("File already has .{} extension", EXTENSION));
            }
            Ok(path.with_extension(EXTENSION))
        } else {
            if path.extension().map_or(true, |e| e != EXTENSION) {
                return Err(anyhow!("File does not have .{} extension", EXTENSION));
            }
            Ok(path.with_extension(""))
        }
    }
}

// 密钥生成工具函数
pub fn generate_keys() -> Result<(String, String)> {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_SIZE)
        .context("Failed to generate RSA key pair")?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("Failed to serialize private key")?
        .to_string();
    let public_pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .context("Failed to serialize public key")?;

    Ok((public_pem, private_pem))
}

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