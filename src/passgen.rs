//  ____  ____     __        __    __  __           _
// |  _ \|  _ \ __ \ \      / /__ |  \/  | __ _ ___| |_ ___ _ __ 
// | |_) | |_) / _` \ \/\ / / _ \| |\/| |/ _` / __| __/ _ \ '__|
// |  _ <|  __/ (_| |\ V  V / (_) | |  | | (_| \__ \ ||  __/ |   
// |_| \_\_|   \__,_| \_/\_/ \___/|_|  |_|\__,_|___/\__\___|_|   
//
// Author : Sidney Zhang <zly@lyzhang.me>
// Date : 2025-07-02
// Version : 0.1.0
// License : Mulan PSL v2
//
// Password generator

use std::collections::HashSet;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;
use zxcvbn::zxcvbn;
use zxcvbn::Score;
use crate::GenArgs;

// 引入编译生成的单词列表
include!(concat!(env!("OUT_DIR"), "/word_data.rs"));

// 单词大写方式枚举
#[derive(Debug, Clone, Copy)]
pub enum Capitalization {
    NoCapitalization,
    CamelCase,
    RandomCase,
}

// 记忆密码生成选项
#[derive(Debug)]
pub struct MemorablePasswordOptions {
    pub word_count: usize,
    pub include_numbers: bool,
    pub separator: char,
    pub capitalization: Capitalization,
}

impl Default for MemorablePasswordOptions {
    fn default() -> Self {
        Self {
            word_count: 4,
            include_numbers: false,
            separator: '-',
            capitalization: Capitalization::CamelCase,
        }
    }
}

struct PasswordOptions {
    length: usize,
    include_uppercase: bool,
    include_lowercase: bool,
    include_numbers: bool,
    include_special: bool,
    url_safe: bool,
    avoid_confusion: bool,
}

impl From<GenArgs> for PasswordOptions {
    fn from(args: GenArgs) -> Self {
        Self {
            length: args.length,
            include_uppercase: !args.no_uppercase,
            include_lowercase: !args.no_lowercase,
            include_numbers: !args.no_numbers,
            include_special: !args.no_special,
            url_safe: args.url_safe,
            avoid_confusion: args.avoid_confusion,
        }
    }
}

pub fn generate_password(options: &PasswordOptions) -> Result<String, String> {
    // Define base character sets
    let mut uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string();
    let mut lowercase = "abcdefghijklmnopqrstuvwxyz".to_string();
    let mut numbers = "0123456789".to_string();
    let mut special = if options.url_safe {
        "-._~".to_string()
    } else {
        "!@#$%^&*()_+-=[]{}|;:,.<>?~".to_string()
    };

    // Remove confusing characters if requested
    if options.avoid_confusion {
        let confusing_chars: HashSet<char> = ['l', 'I', '1', 'O', '0', 'o'].iter().cloned().collect();
        uppercase.retain(|c| !confusing_chars.contains(&c));
        lowercase.retain(|c| !confusing_chars.contains(&c));
        numbers.retain(|c| !confusing_chars.contains(&c));
        special.retain(|c| !confusing_chars.contains(&c));
    }

    // Collect required character sets and check availability
    let mut required_sets = Vec::new();
    if options.include_uppercase {
        if uppercase.is_empty() {
            return Err("Uppercase character set is empty after removing confusing characters".to_string());
        }
        required_sets.push(uppercase.chars().collect::<Vec<_>>());
    }
    if options.include_lowercase {
        if lowercase.is_empty() {
            return Err("Lowercase character set is empty after removing confusing characters".to_string());
        }
        required_sets.push(lowercase.chars().collect::<Vec<_>>());
    }
    if options.include_numbers {
        if numbers.is_empty() {
            return Err("Numbers character set is empty after removing confusing characters".to_string());
        }
        required_sets.push(numbers.chars().collect::<Vec<_>>());
    }
    if options.include_special {
        if special.is_empty() {
            return Err("Special character set is empty after removing confusing characters".to_string());
        }
        required_sets.push(special.chars().collect::<Vec<_>>());
    }

    // Validate at least one character set is selected
    if required_sets.is_empty() {
        return Err("At least one character set must be included".to_string());
    }

    // Validate password length is sufficient for required sets
    if options.length < required_sets.len() {
        return Err(format!("Password length must be at least {} to include all required character sets", required_sets.len()));
    }

    // Build the combined character pool
    let mut char_pool = String::new();
    if options.include_uppercase { char_pool.push_str(&uppercase); }
    if options.include_lowercase { char_pool.push_str(&lowercase); }
    if options.include_numbers { char_pool.push_str(&numbers); }
    if options.include_special { char_pool.push_str(&special); }
    let all_chars: Vec<char> = char_pool.chars().collect();

    // Generate password with at least one character from each required set
    let mut rng = OsRng::default();
    let mut password_chars = Vec::with_capacity(options.length);

    // Add one character from each required set
    for chars in &required_sets {
        password_chars.push(*chars.choose(&mut rng).unwrap());
    }

    // Add remaining characters from combined pool
    for _ in 0..(options.length - required_sets.len()) {
        password_chars.push(*all_chars.choose(&mut rng).unwrap());
    }

    // Shuffle the characters to avoid predictable pattern
    password_chars.shuffle(&mut rng);

    Ok(password_chars.into_iter().collect())
}

/// 生成记忆密码（基于单词列表）
pub fn generate_memorable_password(options: &MemorablePasswordOptions) -> Result<String, String> {
    // 验证单词数量
    if options.word_count < 1 {
        return Err("Word count must be at least 1".to_string());
    }
    if WORDS.is_empty() {
        return Err("Word list is empty".to_string());
    }

    let mut rng = OsRng::default();
    let mut words = Vec::with_capacity(options.word_count);

    // 随机选择单词
    for _ in 0..options.word_count {
        let word = WORDS.choose(&mut rng)
            .ok_or("Failed to select word from list")?;
        words.push(process_word(word, options.capitalization, &mut rng));
    }

    // 添加数字（如果需要）
    let mut password_parts = words;
    if options.include_numbers {
        let number = rng.gen_range(0..=99);
        password_parts.push(number.to_string());
    }

    // 使用分隔符连接所有部分
    Ok(password_parts.join(&options.separator.to_string()))
}

/// 处理单词大小写
fn process_word(word: &str, capitalization: Capitalization, rng: &mut OsRng) -> String {
    match capitalization {
        Capitalization::NoCapitalization => word.to_lowercase(),
        Capitalization::CamelCase => {
            let mut chars: Vec<char> = word.chars().collect();
            if let Some(first) = chars.get_mut(0) {
                *first = first.to_ascii_uppercase();
            }
            chars.into_iter().collect()
        },
        Capitalization::RandomCase => {
            word.chars()
                .map(|c| {
                    if rng.gen_bool(0.5) {
                        c.to_ascii_uppercase()
                    } else {
                        c.to_ascii_lowercase()
                    }
                })
                .collect()
        }
    }
}

pub fn check_url_safe(password: &str) -> bool {
    password.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~'))
}

pub fn check_confusing_chars(password: &str) -> Vec<char> {
    let confusing_chars = ['l', 'I', '1', 'O', '0', 'o'];
    password.chars().filter(|c| confusing_chars.contains(c)).collect()
}

pub fn assess_password_strength(password: &str) -> (String, u8, String) {
    let strength_result = zxcvbn(password, &[]);
    let score = strength_result.score();
    let feedback = strength_result.feedback().map_or_else(
        || String::new(),
        |f| f.suggestions().iter().map(|s| s.to_string()).collect::<Vec<_>>().join(" ")
    );

    // 确定安全评级
    let rating = match score {
        Score::Zero => "极弱",
        Score::One => "弱",
        Score::Two => "中等",
        Score::Three => "强",
        Score::Four => "极强",
        _ => "未知",
    }.to_string();

    (rating, score as u8, feedback)
}

