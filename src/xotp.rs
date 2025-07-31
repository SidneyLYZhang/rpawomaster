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

use totp_rs::{Algorithm, TOTP, Secret, Rfc6238};
use slauth::oath::{hotp, HashesAlgorithm};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

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
}

pub enum XOTPType {
    HOTP,
    TOTP,
}

/// 敏感数据清零
#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct XOTP {
    otptype: XOTPType,
    secret: Vec<u8>, // 加密后的密钥
    algorithm: XOTPAlgorithm,
    digits: u8, // 验证码长度
    counter: Option<u64>, // HOTP 计数器
    interval: Option<u32>, // TOTP 时间间隔
}

impl XOTP {
    pub fn from_text(text: &str) -> Self {
        if is_uri(text) {
            let otptype = which_type(text);
        } else {
            let otptype = XOTPType::TOTP;
        }
    }
}

fn which_type(text: &str) -> XOTPType {
    if text.starts_with("otpauth://totp/") {
        XOTPType::TOTP
    } else if text.starts_with("otpauth://hotp/") {
        XOTPType::HOTP
    } else {
        panic!("Invalid URI");
    }
}

fn is_uri(text: &str) -> bool {
    if text.starts_with("otpauth://") {
        return true;
    } else {
        return false;
    }
}
