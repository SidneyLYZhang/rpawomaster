// XOTP 模块测试文件
// 测试 HOTP/TOTP 功能

use rpawomaster::xotp::{XOTP, XOTPAlgorithm, XOTPType, OtpAlgo};
use rpawomaster::securecrypto::SecureCrypto;

#[cfg(test)]
mod tests {
    use super::*;

    // 测试辅助函数：创建测试用的加密模块
    fn create_test_crypto() -> SecureCrypto {
        SecureCrypto::new().unwrap()
    }

    #[test]
    fn test_xotp_algorithm_conversion() {
        // 测试 XOTPAlgorithm 到 TOTP 算法的转换
        assert_eq!(format!("{:?}", XOTPAlgorithm::SHA1.to_totp()), "SHA1");
        assert_eq!(format!("{:?}", XOTPAlgorithm::SHA256.to_totp()), "SHA256");
        assert_eq!(format!("{:?}", XOTPAlgorithm::SHA512.to_totp()), "SHA512");
        
        // 测试 XOTPAlgorithm 到 HOTP 算法的转换
        let _ = XOTPAlgorithm::SHA1.to_hotp();
        let _ = XOTPAlgorithm::SHA256.to_hotp();
        let _ = XOTPAlgorithm::SHA512.to_hotp();
    }

    #[test]
    fn test_xotp_algorithm_from_str() {
        // 测试从字符串解析算法
        assert_eq!(XOTPAlgorithm::from_str("SHA1"), Some(XOTPAlgorithm::SHA1));
        assert_eq!(XOTPAlgorithm::from_str("SHA-1"), Some(XOTPAlgorithm::SHA1));
        assert_eq!(XOTPAlgorithm::from_str("sha1"), Some(XOTPAlgorithm::SHA1));
        
        assert_eq!(XOTPAlgorithm::from_str("SHA256"), Some(XOTPAlgorithm::SHA256));
        assert_eq!(XOTPAlgorithm::from_str("SHA-256"), Some(XOTPAlgorithm::SHA256));
        assert_eq!(XOTPAlgorithm::from_str("sha256"), Some(XOTPAlgorithm::SHA256));
        
        assert_eq!(XOTPAlgorithm::from_str("SHA512"), Some(XOTPAlgorithm::SHA512));
        assert_eq!(XOTPAlgorithm::from_str("SHA-512"), Some(XOTPAlgorithm::SHA512));
        assert_eq!(XOTPAlgorithm::from_str("sha512"), Some(XOTPAlgorithm::SHA512));
        
        // 测试无效输入
        assert_eq!(XOTPAlgorithm::from_str("INVALID"), None);
        assert_eq!(XOTPAlgorithm::from_str(""), None);
    }

    #[test]
    fn test_xotp_default() {
        let xotp = XOTP::default();
        
        assert!(matches!(xotp.otptype, XOTPType::TOTP));
        assert_eq!(xotp.secret.len(), 0);
        assert!(matches!(xotp.algorithm, XOTPAlgorithm::SHA1));
        assert_eq!(xotp.digits, 6);
        assert!(matches!(xotp.algo, OtpAlgo::Totp { interval: 30 }));
        assert_eq!(xotp.issuer_label, None);
    }

    #[test]
    fn test_xotp_from_secret() {
        let crypto = create_test_crypto();
        let secret = "JBSWY3DPEHPK3PXP";
        
        let xotp = XOTP::from_text(secret, &crypto);
        
        assert!(matches!(xotp.otptype, XOTPType::TOTP));
        assert!(xotp.secret.len() > 0); // 加密后的密钥不应为空
        assert!(matches!(xotp.algorithm, XOTPAlgorithm::SHA1));
        assert_eq!(xotp.digits, 6);
        assert!(matches!(xotp.algo, OtpAlgo::Totp { interval: 30 }));
        assert_eq!(xotp.issuer_label, None);
    }

    #[test]
    fn test_xotp_from_uri_totp() {
        let crypto = create_test_crypto();
        let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30";
        
        let xotp = XOTP::from_text(uri, &crypto);
        
        assert!(matches!(xotp.otptype, XOTPType::TOTP));
        assert!(xotp.secret.len() > 0);
        assert!(matches!(xotp.algorithm, XOTPAlgorithm::SHA1));
        assert_eq!(xotp.digits, 6);
        assert!(matches!(xotp.algo, OtpAlgo::Totp { interval: 30 }));
        assert_eq!(xotp.issuer_label, Some("Example:alice@google.com".to_string()));
    }

    #[test]
    fn test_xotp_from_uri_hotp() {
        let crypto = create_test_crypto();
        let uri = "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&counter=100";
        
        let xotp = XOTP::from_uri(uri, &crypto);
        
        assert!(matches!(xotp.otptype, XOTPType::HOTP));
        assert!(xotp.secret.len() > 0);
        assert!(matches!(xotp.algorithm, XOTPAlgorithm::SHA256));
        assert_eq!(xotp.digits, 8);
        assert!(matches!(xotp.algo, OtpAlgo::Hotp { counter: 100 }));
        assert_eq!(xotp.issuer_label, Some("Example:alice@google.com".to_string()));
    }

    #[test]
    fn test_xotp_from_text_secret() {
        let crypto = create_test_crypto();
        let secret = "JBSWY3DPEHPK3PXP";
        
        let xotp = XOTP::from_text(secret, &crypto);
        
        assert!(matches!(xotp.otptype, XOTPType::TOTP));
        assert!(xotp.secret.len() > 0);
        assert!(matches!(xotp.algorithm, XOTPAlgorithm::SHA1));
        assert_eq!(xotp.digits, 6);
        assert!(matches!(xotp.algo, OtpAlgo::Totp { interval: 30 }));
    }

    #[test]
    fn test_xotp_from_text_uri() {
        let crypto = create_test_crypto();
        let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        
        let xotp = XOTP::from_text(uri, &crypto);
        
        assert!(matches!(xotp.otptype, XOTPType::TOTP));
        assert!(xotp.secret.len() > 0);
        assert_eq!(xotp.issuer_label, Some("Example:alice@google.com".to_string()));
    }

    #[test]
    fn test_is_uri() {
        assert!(super::super::is_uri("otpauth://totp/test"));
        assert!(super::super::is_uri("otpauth://hotp/test"));
        assert!(!super::super::is_uri("not-a-uri"));
        assert!(!super::super::is_uri(""));
        assert!(!super::super::is_uri("http://example.com"));
    }

    #[test]
    fn test_generate_totp_code() {
        let crypto = create_test_crypto();
        let secret = "JBSWY3DPEHPK3PXP";
        let xotp = XOTP::from_secret(secret, &crypto);
        
        // 生成TOTP代码，应该返回6位数字字符串
        let code = xotp.generate_totp_code(&crypto);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        
        // 验证代码格式
        let code_num: u32 = code.parse().unwrap();
        assert!(code_num <= 999999);
    }

    #[test]
    fn test_generate_hotp_code() {
        let crypto = create_test_crypto();
        let secret = "JBSWY3DPEHPK3PXP";
        let mut xotp = XOTP {
            otptype: XOTPType::HOTP,
            secret: crypto.encrypt_string(secret).unwrap(),
            algorithm: XOTPAlgorithm::SHA1,
            digits: 6,
            algo: OtpAlgo::Hotp { counter: 1 },
            issuer_label: None,
        };
        
        let initial_counter = match xotp.algo {
            OtpAlgo::Hotp { counter } => counter,
            _ => 0,
        };
        
        // 生成HOTP代码
        let code = xotp.generate_hotp_code(&crypto);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        
        // 验证计数器已增加
        match xotp.algo {
            OtpAlgo::Hotp { counter } => {
                assert_eq!(counter, initial_counter + 1);
            }
            _ => panic!("Expected HOTP"),
        }
    }

    #[test]
    fn test_increment_counter() {
        let crypto = create_test_crypto();
        let secret = "JBSWY3DPEHPK3PXP";
        
        // 测试HOTP计数器增加
        let mut xotp_hotp = XOTP {
            otptype: XOTPType::HOTP,
            secret: crypto.encrypt_string(secret).unwrap(),
            algorithm: XOTPAlgorithm::SHA1,
            digits: 6,
            algo: OtpAlgo::Hotp { counter: 100 },
            issuer_label: None,
        };
        
        assert!(xotp_hotp.increment_counter());
        match xotp_hotp.algo {
            OtpAlgo::Hotp { counter } => assert_eq!(counter, 101),
            _ => panic!("Expected HOTP"),
        }
        
        // 测试TOTP计数器不增加
        let mut xotp_totp = XOTP {
            otptype: XOTPType::TOTP,
            secret: crypto.encrypt_string(secret).unwrap(),
            algorithm: XOTPAlgorithm::SHA1,
            digits: 6,
            algo: OtpAlgo::Totp { interval: 30 },
            issuer_label: None,
        };
        
        assert!(!xotp_totp.increment_counter());
        match xotp_totp.algo {
            OtpAlgo::Totp { interval } => assert_eq!(interval, 30),
            _ => panic!("Expected TOTP"),
        }
    }

    #[test]
    fn test_get_remaining_seconds() {
        let crypto = create_test_crypto();
        let secret = "JBSWY3DPEHPK3PXP";
        
        // 测试TOTP获取剩余时间
        let xotp_totp = XOTP {
            otptype: XOTPType::TOTP,
            secret: crypto.encrypt_string(secret).unwrap(),
            algorithm: XOTPAlgorithm::SHA1,
            digits: 6,
            algo: OtpAlgo::Totp { interval: 30 },
            issuer_label: None,
        };
        
        let remaining = xotp_totp.get_remaining_seconds();
        assert!(remaining.is_some());
        let secs = remaining.unwrap();
        assert!(secs <= 30);
        
        // 测试HOTP没有剩余时间
        let xotp_hotp = XOTP {
            otptype: XOTPType::HOTP,
            secret: crypto.encrypt_string(secret).unwrap(),
            algorithm: XOTPAlgorithm::SHA1,
            digits: 6,
            algo: OtpAlgo::Hotp { counter: 100 },
            issuer_label: None,
        };
        
        assert!(xotp_hotp.get_remaining_seconds().is_none());
    }

    #[test]
    fn test_xotp_serialization_deserialization() {
        let crypto = create_test_crypto();
        let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60";
        let xotp = XOTP::from_uri(uri, &crypto);
        
        // 序列化
        let serialized = serde_json::to_string(&xotp).unwrap();
        assert!(serialized.contains("TOTP"));
        assert!(serialized.contains("SHA256"));
        
        // 反序列化
        let deserialized: XOTP = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized.otptype, XOTPType::TOTP));
        assert!(matches!(deserialized.algorithm, XOTPAlgorithm::SHA256));
        assert_eq!(deserialized.digits, 8);
        match deserialized.algo {
            OtpAlgo::Totp { interval } => assert_eq!(interval, 60),
            _ => panic!("Expected TOTP"),
        }
    }

    #[test]
    fn test_xotp_with_different_digits() {
        let crypto = create_test_crypto();
        let secret = "JBSWY3DPEHPK3PXP";
        
        // 测试不同位数的TOTP
        for &digits in &[6, 7, 8] {
            let xotp = XOTP {
                otptype: XOTPType::TOTP,
                secret: crypto.encrypt_string(secret).unwrap(),
                algorithm: XOTPAlgorithm::SHA1,
                digits,
                algo: OtpAlgo::Totp { interval: 30 },
                issuer_label: None,
            };
            
            let code = xotp.generate_totp_code(&crypto);
            assert_eq!(code.len(), digits as usize);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn test_xotp_with_different_algorithms() {
        let crypto = create_test_crypto();
        let secret = "JBSWY3DPEHPK3PXP";
        
        // 测试不同算法的TOTP
        for algorithm in &[XOTPAlgorithm::SHA1, XOTPAlgorithm::SHA256, XOTPAlgorithm::SHA512] {
            let xotp = XOTP {
                otptype: XOTPType::TOTP,
                secret: crypto.encrypt_string(secret).unwrap(),
                algorithm: algorithm.clone(),
                digits: 6,
                algo: OtpAlgo::Totp { interval: 30 },
                issuer_label: None,
            };
            
            let code = xotp.generate_totp_code(&crypto);
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn test_xotp_uri_with_missing_parameters() {
        let crypto = create_test_crypto();
        
        // 测试缺少参数的URI，应该使用默认值
        let uri = "otpauth://totp/TestUser";
        let xotp = XOTP::from_uri(uri, &crypto);
        
        assert!(matches!(xotp.otptype, XOTPType::TOTP));
        assert!(matches!(xotp.algorithm, XOTPAlgorithm::SHA1)); // 默认值
        assert_eq!(xotp.digits, 6); // 默认值
        match xotp.algo {
            OtpAlgo::Totp { interval } => assert_eq!(interval, 30), // 默认值
            _ => panic!("Expected TOTP"),
        }
    }
}