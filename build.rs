use std::{env, fs, path::Path};
use std::io::{BufRead, BufReader};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("word_data.rs");
    
    // 读取数据文件
    let data_file = "data/wordlist.txt";
    let file = fs::File::open(data_file).expect("Failed to open data file");
    let reader = BufReader::new(file);
    
    // 处理数据
    let mut word_array = Vec::new();
    
    for line in reader.lines() {
        let line = line.expect("Error reading line");
        if line.trim().is_empty() {
            continue; // 跳过空行
        }
        
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 2 {
            panic!("Invalid data format: {}", line);
        }
        
        let word = parts[1].trim();
        
        // 收集所有单词
        word_array.push(format!("\"{}\"", word));
    }
    
    // 生成Rust代码
    let code = format!(r#"pub static WORDS: [&str; {}] = [{}];"#,
        word_array.len(),
        word_array.join(", ")
    );
    
    // 写入生成的文件
    fs::write(dest_path, code).expect("Failed to write generated file");
    
    // 确保数据文件变化时重建
    println!("cargo:rerun-if-changed={}", data_file);
}