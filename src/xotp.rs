//  ____  ____     __        __    __  __           _
// |  _ \|  _ \ __ \ \      / /__ |  \/  | __ _ ___| |_ ___ _ __ 
// | |_) | |_) / _` \ \ /\ / / _ \| |\/| |/ _` / __| __/ _ \ '__|
// |  _ <|  __/ (_| |\ V  V / (_) | |  | | (_| \__ \ ||  __/ |   
// |_| \_\_|   \__,_| \_/\_/ \___/|_|  |_|\__,_|___/\__\___|_|   
//
// Author : Sidney Zhang <zly@lyzhang.me>
// Date : 2025-07-31
// Version : 0.1.0
// License : Mulan PSL v2
//
// HOTP/TOTP

use totp_rs::{Algorithm, TOTP, Secret};
use slauth::oath::{hotp, HashesAlgorithm};
use serde::{Deserialize, Serialize};
use sled::IVec;
use url::Url;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::securecrypto::SecureCrypto;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum XOTPAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl XOTPAlgorithm {
    pub fn to_totp(&self) -> Algorithm {
        match self {
            XOTPAlgorithm::SHA1 => Algorithm::SHA1,
            XOTPAlgorithm::SHA256 => Algorithm::SHA256,
            XOTPAlgorithm::SHA512 => Algorithm::SHA512,
        }
    }
    pub fn to_hotp(&self) -> HashesAlgorithm {
        match self {
            XOTPAlgorithm::SHA1 => HashesAlgorithm::SHA1,
            XOTPAlgorithm::SHA256 => HashesAlgorithm::SHA256,
            XOTPAlgorithm::SHA512 => HashesAlgorithm::SHA512,
        }
    }
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "SHA1" | "SHA-1" => Some(XOTPAlgorithm::SHA1),
            "SHA256" | "SHA-256" => Some(XOTPAlgorithm::SHA256),
            "SHA512" | "SHA-512" => Some(XOTPAlgorithm::SHA512),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum XOTPType {
    HOTP,
    TOTP,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OtpAlgo {
    Hotp { counter: u64 }, // HOTP 计数器
    Totp { interval: u64 }, // TOTP 时间间隔 一般为 30 秒
}

/// 敏感数据清零
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XOTP {
    pub otptype: XOTPType,
    pub secret: Vec<u8>, // 加密后的密钥
    pub algorithm: XOTPAlgorithm,
    pub digits: u8, // 验证码长度
    pub algo: OtpAlgo,
    pub issuer_label: Option<String>, // 服务提供商名称
}

impl Default for XOTP {
    fn default() -> Self {
        Self {
            otptype: XOTPType::TOTP,
            secret: Vec::new(),
            algorithm: XOTPAlgorithm::SHA1,
            digits: 6,
            algo: OtpAlgo::Totp { interval: 30 },
            issuer_label: None,
        }
    }
}

impl XOTP {
    pub fn from_text(text: &str, crypto: &SecureCrypto) -> Self {
        if is_uri(text) {
            Self::from_uri(text, crypto)
        } else {
            Self::from_secret(text, crypto)

        }
    }

    fn from_secret(secret: &str, crypto: &SecureCrypto) -> Self {
        let cleaned_secret = secret.trim().replace(' ', "");
        let encrypted_secret = crypto.encrypt_string(&cleaned_secret)
                                            .expect("Failed to encrypt secret");
        XOTP {
            otptype: XOTPType::TOTP,
            secret: encrypted_secret,
            algorithm: XOTPAlgorithm::SHA1,
            digits: 6,
            algo: OtpAlgo::Totp { interval: 30 },
            issuer_label: None,
        }
    }

    fn from_uri(uri: &str, crypto: &SecureCrypto) -> Self {
        let url = Url::parse(uri).expect("Invalid URI");
        let mut xotp = XOTP::default();

        // 解析服务商与标签
        let path = url.path();
        xotp.issuer_label = Some(path[1..].to_string());
        // 解析类型
        if let Some(host) = url.host_str() {
            if host.contains("hotp") {
                xotp.otptype = XOTPType::HOTP;
            } else if host.contains("totp") {
                xotp.otptype = XOTPType::TOTP;
            }
        }

        // 解析查询参数
        let query_pairs = url.query_pairs();
        for (key, value) in query_pairs {
            match key.as_ref() {
                "secret" => {
                    let encrypted_secret = crypto.encrypt_string(&value)
                                            .expect("Failed to encrypt secret");
                    xotp.secret = encrypted_secret;
                }
                "algorithm" => {
                    xotp.algorithm = XOTPAlgorithm::from_str(&value).unwrap_or(XOTPAlgorithm::SHA1);
                }
                "digits" => {
                    xotp.digits = value.parse().unwrap_or(6);
                }
                "period" => {
                    xotp.algo = OtpAlgo::Totp { interval: value.parse().unwrap_or(30) };
                }
                "counter" => {
                    xotp.algo = OtpAlgo::Hotp { counter: value.parse().unwrap_or(0) };
                }
                _ => {}
            }
        }

        xotp
    }

    pub fn generate_totp_code(&self, crypto: &SecureCrypto) -> String {
        let secret = crypto.decrypt_string(&IVec::from(self.secret.as_slice()))
                                            .expect("Failed to decrypt secret");
        
        let totp = TOTP::new(
            self.algorithm.to_totp(),
            self.digits.into(),
            1,
            match &self.algo {
                OtpAlgo::Totp { interval } => *interval,
                _ => 30,
            },
            Secret::Encoded(secret).to_bytes().expect("Failed to convert secret"),
        ).expect("Failed to create TOTP");
        totp.generate_current().unwrap_or_default()
    }

    pub fn generate_hotp_code(&mut self, crypto: &SecureCrypto) -> String {
        let secret = crypto.decrypt_string(&IVec::from(self.secret.as_slice()))
                                            .expect("Failed to decrypt secret");
        let counter = match &self.algo {
            OtpAlgo::Hotp { counter } => *counter,
            _ => 1,
        };
        let hotp_builder = hotp::HOTPBuilder::new()
            .algorithm(self.algorithm.to_hotp())
            .digits(self.digits.into())
            .counter(counter)
            .secret(&secret.as_bytes())
            .build();
        self.increment_counter();
        hotp_builder.r#gen()
    }

    /// 获取TOTP的剩余有效时间（秒）
    pub fn get_remaining_seconds(&self) -> Option<u32> {
        if let XOTPType::TOTP = self.otptype {
            let interval = match &self.algo {
                OtpAlgo::Totp { interval } => *interval,
                _ => 30,
            }.max(30) as u64; // 确保最小为30秒，避免除零错误
            
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
                
            let elapsed = now % interval;
            Some((interval - elapsed) as u32)
        } else {
            None
        }
    }

    /// 增加HOTP计数器
    pub fn increment_counter(&mut self) -> bool {
        if let OtpAlgo::Hotp { ref mut counter } = self.algo {
            *counter += 1;
            true
        } else {
            false
        }
    }
}

fn is_uri(text: &str) -> bool {
    text.starts_with("otpauth://")
}

pub fn generate_code(xotp: &mut XOTP, crypto: &SecureCrypto) -> String {
    match xotp.otptype {
        XOTPType::TOTP => {
            xotp.generate_totp_code(crypto)
        },
        XOTPType::HOTP => {
            xotp.generate_hotp_code(crypto)
        }
    }
}
