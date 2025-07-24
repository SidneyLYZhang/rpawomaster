use rpawomaster::setclip::copy_to_clipboard;
use arboard::Clipboard;
use std::env;

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
fn test_daemon_task_clears_only_unmodified_content() {
    // 设置环境变量以直接运行守护进程逻辑
    unsafe {
        env::set_var("CLIPBOARD_DAEMON", "1");
        env::set_var("DYNAMIC_INFO", "test_password_456");
    }

    let mut guard = ClipboardGuard::new();
    let clipboard = &mut guard.clipboard;

    // 情况1: 剪贴板内容未修改 - 应该被清空
    clipboard.set_text("test_password_456").unwrap();
    assert!(copy_to_clipboard("test_password_456", 1).is_ok());
    let content_after = clipboard.get_text().unwrap_or_default();
    assert_eq!(content_after, "", "Should clear unmodified content");

    // 情况2: 剪贴板内容已修改 - 不应该被清空
    clipboard.set_text("different_content").unwrap();
    assert!(copy_to_clipboard("test_password_456", 1).is_ok());
    let content_after_modified = clipboard.get_text().unwrap_or_default();
    assert_eq!(content_after_modified, "different_content", "Should not clear modified content");

    // 清理由测试设置的环境变量
    unsafe {
        env::remove_var("CLIPBOARD_DAEMON");
        env::remove_var("DYNAMIC_INFO");
    }
    // 恢复测试前粘贴板数据
    drop(guard);
}