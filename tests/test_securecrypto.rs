use rpawomaster::securecrypto::{SecureCrypto, generate_rsa_keypair};
use sled::IVec;
use tempfile::tempdir;
use std::fs;
use walkdir::WalkDir;

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
    crypto.encrypt_path(&temp_file_path, &encrypted_path).expect("File encryption failed");

    // 验证加密文件存在
    assert!(encrypted_file_path.exists(), "Encrypted file not created");

    // 删除原始文件以确保解密效果
    fs::remove_file(&temp_file_path).expect("Failed to remove original file");

    // 创建解密文件的目标路径
    let decrypted_path = temp_dir.path();
    let decrypted_file_path = decrypted_path.join(filename);
    
    // 解密文件
    crypto.decrypt_path(&encrypted_file_path, &decrypted_path).expect("File decryption failed");

    // 验证解密文件存在且内容正确
    assert!(decrypted_file_path.exists(), "Decrypted file not created");
    let decrypted_content = fs::read(&decrypted_file_path).expect("Failed to read decrypted file");
    assert_eq!(decrypted_content, test_content, "Decrypted file content does not match original");
}

#[test]
fn test_tar_gz_pack_unpack() {
    // Generate RSA key pair
    let (private_pem, public_pem) = generate_rsa_keypair().expect("Failed to generate RSA key pair");
    let crypto = SecureCrypto::from_pem_keys(&public_pem, &private_pem).expect("Failed to create SecureCrypto instance");
    
    // Create temporary directories
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let source_dir = temp_dir.path().join("source_dir");
    let tar_path = temp_dir.path().join("test_archive.tgz");
    let extract_dir = temp_dir.path().join("extracted_dir");
    
    // Create test directory structure
    fs::create_dir(&source_dir).expect("Failed to create source directory");
    
    // Create files and subdirectories
    fs::write(source_dir.join("file1.txt"), "Test content 1").expect("Failed to write file1");
    fs::write(source_dir.join("file2.bin"), vec![0x00, 0x01, 0x02, 0xFF]).expect("Failed to write binary file");
    
    let subdir = source_dir.join("subdir");
    fs::create_dir(&subdir).expect("Failed to create subdirectory");
    fs::write(subdir.join("file3.txt"), "Nested file content").expect("Failed to write nested file");
    
    // Create empty directory
    let empty_dir = source_dir.join("empty_dir");
    fs::create_dir(&empty_dir).expect("Failed to create empty directory");
    
    // Pack directory into tgz archive
    crypto.create_tar_archive(&source_dir, &tar_path).expect("Failed to create tgz archive");
    
    // Verify archive was created
    assert!(tar_path.exists(), "Archive file not created");
    assert!(tar_path.metadata().expect("Failed to get metadata").len() > 0, "Archive file is empty");
    
    // Extract the archive
    crypto.extract_tar_archive(&tar_path, &extract_dir).expect("Failed to extract tgz archive");
    
    // Verify extracted contents
    // Check regular files
    let extracted_file1 = extract_dir.join("file1.txt");
    assert!(extracted_file1.exists(), "Extracted file1.txt not found");
    let content1 = fs::read_to_string(extracted_file1).expect("Failed to read extracted file1");
    assert_eq!(content1, "Test content 1", "Content mismatch for file1.txt");
    
    let extracted_bin = extract_dir.join("file2.bin");
    assert!(extracted_bin.exists(), "Extracted file2.bin not found");
    let bin_content = fs::read(extracted_bin).expect("Failed to read binary file");
    assert_eq!(bin_content, vec![0x00, 0x01, 0x02, 0xFF], "Binary content mismatch");
    
    // Check nested files
    let extracted_nested = extract_dir.join("subdir/file3.txt");
    assert!(extracted_nested.exists(), "Extracted nested file not found");
    let nested_content = fs::read_to_string(extracted_nested).expect("Failed to read nested file");
    assert_eq!(nested_content, "Nested file content", "Content mismatch for nested file");
    
    // Check empty directory
    let extracted_empty = extract_dir.join("empty_dir");
    assert!(extracted_empty.exists(), "Empty directory not extracted");
    assert!(extracted_empty.is_dir(), "Extracted empty_dir is not a directory");
    assert!(extracted_empty.read_dir().expect("Failed to read empty directory").next().is_none(), "Extracted empty directory is not empty");
    
    // Clean up
    temp_dir.close().expect("Failed to close temp directory");
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
    let encrypted_path = temp_dir_path.join("complex_test_dir.tgz.esz");

    // 测试目录加密
    crypto.encrypt_path(&test_dir, &temp_dir_path).expect("Directory encryption failed");
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
    
    let empty_encrypted_path = temp_dir_path.join("empty_test_dir.tgz.esz");
    crypto.encrypt_path(&empty_test_dir, &temp_dir_path).expect("Empty directory encryption failed");
    assert!(empty_encrypted_path.exists(), "Empty directory encryption failed");

    let empty_decrypted_dir = temp_dir_path.join("decrypted_empty_dir");
    crypto.decrypt_path(&empty_encrypted_path, &empty_decrypted_dir).expect("Empty directory decryption failed");
    assert!(empty_decrypted_dir.exists(), "Empty directory decryption failed");
    assert!(empty_decrypted_dir.read_dir().unwrap().next().is_none(), "Decrypted empty directory should be empty");
}

#[test]
fn test_save_and_read_keypair() {
    use rpawomaster::securecrypto::{save_keypair, read_keypair};
    
    // 生成密钥对
    let (private_pem, public_pem) = generate_rsa_keypair().expect("Failed to generate RSA key pair");
    
    // 创建临时目录
    let temp_dir = tempdir().expect("Failed to create temp directory");
    let temp_dir_path = temp_dir.path();
    
    // 测试保存密钥对
    save_keypair(private_pem.clone(), public_pem.clone(), temp_dir_path)
        .expect("Failed to save keypair");
    
    // 验证文件是否已创建
    let private_key_path = temp_dir_path.join("private_key.esz");
    let public_key_path = temp_dir_path.join("public_key.esz");
    
    assert!(private_key_path.exists(), "Private key file not created");
    assert!(public_key_path.exists(), "Public key file not created");
    
    // 验证文件内容不为空
    let private_key_content = fs::read_to_string(&private_key_path).expect("Failed to read private key file");
    let public_key_content = fs::read_to_string(&public_key_path).expect("Failed to read public key file");
    
    assert!(!private_key_content.is_empty(), "Private key file is empty");
    assert!(!public_key_content.is_empty(), "Public key file is empty");
    
    // 验证内容匹配
    assert_eq!(private_key_content, private_pem, "Private key content mismatch");
    assert_eq!(public_key_content, public_pem, "Public key content mismatch");
    
    // 测试读取密钥对
    let (read_private, read_public) = read_keypair(temp_dir_path)
        .expect("Failed to read keypair");
    
    // 验证读取的内容与原始内容匹配
    assert_eq!(read_private, private_pem, "Read private key does not match original");
    assert_eq!(read_public, public_pem, "Read public key does not match original");
    
    // 测试使用读取的密钥创建SecureCrypto实例
    let crypto_from_read = SecureCrypto::from_pem_keys(&read_public, &read_private)
        .expect("Failed to create SecureCrypto from read keys");
    
    // 验证密钥可用性：加密解密测试
    let test_str = "Test string for keypair functionality";
    let encrypted = crypto_from_read.encrypt_string(test_str)
        .expect("Failed to encrypt with read keys");
    let decrypted = crypto_from_read.decrypt_string(&IVec::from(encrypted))
        .expect("Failed to decrypt with read keys");
    
    assert_eq!(decrypted, test_str, "Decrypted string does not match original");
}