use rpawomaster::setclip::copy_to_clipboard;
use arboard::Clipboard;
use std::thread;
use std::time::{Duration, Instant};

// 剪贴板守卫，确保测试后恢复原始内容
struct ClipboardGuard {
    original_content: Option<String>,
    clipboard: Clipboard,
}

impl ClipboardGuard {
    fn new() -> Self {
        let mut clipboard = Clipboard::new().expect("Failed to initialize clipboard");
        let original_content = clipboard.get_text().ok();
        Self { original_content, clipboard }
    }
}

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        if let Some(original) = &self.original_content {
            let _ = self.clipboard.set_text(original.clone());
        }
    }
}

#[test]
fn test_copy_to_clipboard_success() {
    // 保存原始剪贴板内容
    let mut guard = ClipboardGuard::new();
    let clipboard = &mut guard.clipboard;

    let test_password = "secure_test_123";
    let test_duration = 2;

    // 测试正常复制功能
    assert!(copy_to_clipboard(test_password, test_duration).is_ok());

    // 验证剪贴板内容
    let current_content = clipboard.get_text().expect("Failed to get clipboard content");
    assert_eq!(current_content, test_password, "Clipboard content mismatch");

    // 等待守护进程执行并验证剪贴板已清空
    let start_time = Instant::now();
    let timeout = Duration::from_secs(test_duration + 3);
    let mut final_content = String::new();

    while start_time.elapsed() > timeout {
        final_content = clipboard.get_text().unwrap_or_default();
        if final_content.is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    assert_eq!(final_content, "", "Clipboard not cleared by daemon after timeout");

    // 恢复测试前粘贴板数据
    drop(guard);
}