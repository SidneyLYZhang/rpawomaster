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
use cbc::{Decryptor, Encryptor};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::LineEnding;
use sled::IVec;
use std::{
    fs::{self, File}, io::{self, Read, Write}, path::Path
};
use std::io::{BufReader, BufWriter};
use tar::{Archive, Builder};
use flate2::{write::GzEncoder, Compression};
use flate2::read::GzDecoder;
use tempfile::tempdir;
use walkdir::WalkDir;
use rand::rngs::OsRng;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

const EXTENSION: &str = "esz";
const RSA_KEY_SIZE: usize = 4096;

pub struct SecureCrypto {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl SecureCrypto {
    pub fn new() -> Result<Self> {
        let keys = generate_rsa_keypair().unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(&keys.0).unwrap();
        let public_key = RsaPublicKey::from_public_key_pem(&keys.1).unwrap();
        Ok(Self {
            private_key,
            public_key,
        })
    }
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

        // 验证AES密钥长度
        if aes_key.len() != 32 {
            return Err(anyhow!("Invalid AES key length: expected 32 bytes, got {}", aes_key.len()));
        }

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
        
        if source_path.is_file() && source_path.extension().map_or(false, |e| e == EXTENSION) {
            let name = source_path.file_stem().unwrap().to_str().unwrap();
            // 检查目标路径：如果是目录，则解压；如果是文件，则解密为文件
            if name.contains(".tgz") {
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

    /// 创建 tar 归档文件
    pub fn create_tar_archive(&self, source_dir: &Path, tar_path: &Path) -> Result<()> {
        // 把 `src_dir` 整个目录打包成 `dst_file`。
        // 如果 `dst_file` 以 `.gz` / `.tgz` 结尾，就自动用 gzip 压缩。
        // 创建输出文件
        let out_file = File::create(tar_path)?;

        // 根据扩展名决定是否压缩
        let extension = tar_path.extension().and_then(|e| e.to_str());
        let use_gzip = matches!(extension, Some("gz") | Some("tgz") | Some("esz"));

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

    /// 解压 tar 归档文件
    pub fn extract_tar_archive(&self, tar_path: &Path, output_dir: &Path) -> Result<()> {
        // 创建或清空输出目录
        if !output_dir.exists() {
            fs::create_dir_all(output_dir)?;
        }

        // 根据扩展名决定是否用 gzip 解码
        let extension = tar_path.extension().and_then(|e| e.to_str());
        let use_gzip = matches!(extension, Some("gz") | Some("tgz") | Some("esz"));


        let file = File::open(tar_path)?;
        let mut archive = if use_gzip {
            let dec = GzDecoder::new(file);
            Archive::new(Box::new(dec) as Box<dyn Read>)
        } else {
            Archive::new(Box::new(file) as Box<dyn Read>)
        };

        // 手动解包每个条目以避免Windows权限问题
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?;
            let full_path = output_dir.join(path);
            
            // 确保父目录存在
            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent)?;
            }
            
            // 解包文件
            entry.unpack(&full_path)?;
        }
        Ok(())
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
        let mut reader = BufReader::new(&mut input_file);
        reader.read_to_end(&mut data)?;

        // 生成随机AES密钥和IV
        let (aes_key, iv) = self.generate_aes_components();

        // 加密内容
        let encrypted_data = self.aes_encrypt(data.as_ref(), &aes_key, &iv).unwrap();

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
        let mut result = Vec::with_capacity(4 + encrypted_key.len() + 16 + encrypted_data.len());
        result.extend_from_slice(&(encrypted_key.len() as u32).to_le_bytes());
        result.extend_from_slice(&encrypted_key);
        result.extend_from_slice(&iv);
        result.extend_from_slice(&encrypted_data);

        // 确保输出目录存在
        if !output_path.exists() {
            fs::create_dir_all(output_path)?;
        }
        let output_file_path = output_path.join(format!("{}.{}", filename, EXTENSION));
        
        // 写入加密文件
        let mut output_file = File::create(&output_file_path).unwrap();
        let mut writer = BufWriter::new(&mut output_file);
        writer
            .write_all(&result).unwrap();

        Ok(())
    }

    fn decrypt_file(&self, input_path: &Path, output_path: &Path) -> Result<()> {
        if !input_path.exists() {
            return Err(anyhow!("Input file does not exist"));
        }
        if !input_path.extension().map_or(false, |e| e == EXTENSION) {
            return Err(anyhow!("Invalid input file extension"));
        }

        let mut input_file = File::open(input_path)
            .with_context(|| format!("Failed to open input file: {:?}", input_path)).unwrap();
        let filename = input_path.file_stem()          // -> Some(OsStr)
                                        .and_then(|s| s.to_str()) // -> Option<&str>
                                        .unwrap_or("");
        
        // 读取加密内容
        let mut encrypted_data = Vec::new();
        let mut reader = BufReader::new(&mut input_file);
        reader
            .read_to_end(&mut encrypted_data)
            .context("Failed to read encrypted data")?;

        // 解析数据包结构
        if encrypted_data.len() < 4 + 16 {
            return Err(anyhow!("Invalid encrypted data format: too short ({} bytes)", encrypted_data.len()));
        }

        let key_len = u32::from_le_bytes([encrypted_data[0], encrypted_data[1], encrypted_data[2], encrypted_data[3]]) as usize;
        let key_start = 4;
        let key_end = key_start + key_len;
        let iv_start = key_end;
        let iv_end = iv_start + 16;
        let ciphertext_start = iv_end;

        if encrypted_data.len() < ciphertext_start {
            return Err(anyhow!("Invalid encrypted data format: key_len {} exceeds data length {} (needs at least {})", 
                                key_len, encrypted_data.len(), ciphertext_start));
        }

        // 提取各部分数据
        let encrypted_key = &encrypted_data[key_start..key_end];
        let iv = &encrypted_data[iv_start..iv_end];
        let ciphertext = &encrypted_data[ciphertext_start..];

        // 用RSA解密AES密钥
        let aes_key = self
            .private_key
            .decrypt(Oaep::new::<sha2::Sha256>(), encrypted_key)
            .context("RSA decryption failed").unwrap();

        // 验证AES密钥长度
        if aes_key.len() != 32 {
            return Err(anyhow!("Invalid AES key length: expected 32 bytes, got {}", aes_key.len()));
        }

        // 用AES解密文本
        let decrypted_data = self.aes_decrypt(&ciphertext, &aes_key, &iv).unwrap();

        // 确保输出目录存在
        if !output_path.exists() {
            fs::create_dir_all(output_path)?;
        }

        // 写入原始文件
        let output_file_path = output_path.join(filename);
        
        let mut output_file = File::create(&output_file_path).unwrap();
        let mut writer = BufWriter::new(&mut output_file);
        writer
            .write_all(&decrypted_data)
            .context("Failed to write decrypted data").unwrap();

        Ok(())
    }

    fn encrypt_dir(&self, dir_path: &Path, target_path: &Path) -> Result<()> {
        // 创建临时tar文件
        let filename = dir_path.file_name()          // -> Some(OsStr)
                                        .and_then(|s| s.to_str()) // -> Option<&str>
                                        .unwrap_or("");
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let temp_tar_path = temp_dir.path().join(format!("{}.tgz", filename));
        
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
        let filename = input_path.file_stem()          // -> Some(OsStr)
                                        .and_then(|s| s.to_str()) // -> Option<&str>
                                        .unwrap_or("");

        
        // 解密tar文件到临时目录
        let decrypted_tar_path = temp_dir.path();
        self.decrypt_file(input_path, &decrypted_tar_path)?;
        
        // 确保输出目录存在
        if !output_dir.exists() {
            fs::create_dir_all(output_dir)?;
        }
        
        // 解包tar文件到指定输出目录
        let tar_path = decrypted_tar_path.join(filename);
        self.extract_tar_archive(&tar_path, output_dir)?;
        
        // 临时目录自动删除
        temp_dir.close()?;
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

pub fn save_keypair(encrypted_private_key: String, public_key: String, path: &Path) -> Result<(), String> {
    let private_key_path = path.join("prikey.esz");
    let public_key_path = path.join("pubkey.esz");

    let mut private_key_file = File::create(&private_key_path)
        .map_err(|e| format!("Failed to create file: {}", e))?;
    let mut public_key_file = File::create(&public_key_path)
        .map_err(|e| format!("Failed to create file: {}", e))?;
    private_key_file.write_all(encrypted_private_key.as_bytes())
        .map_err(|e| format!("Failed to write private key: {}", e))?;
    public_key_file.write_all(public_key.as_bytes())
        .map_err(|e| format!("Failed to write public key: {}", e))?;
    Ok(())
}

pub fn read_keypair(path: &Path) -> Result<(String, String), String> {
    let private_key_path = path.join("prikey.esz");
    let public_key_path = path.join("pubkey.esz");

    let private_key_file = File::open(&private_key_path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    let public_key_file = File::open(&public_key_path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    let private_key = io::read_to_string(private_key_file)
        .map_err(|e| format!("Failed to read private key: {}", e))?;
    let public_key = io::read_to_string(public_key_file)
        .map_err(|e| format!("Failed to read public key: {}", e))?;
    Ok((private_key, public_key))
}
