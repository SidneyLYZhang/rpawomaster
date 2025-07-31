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
// Clipboard handler

use arboard::Clipboard;
use std::{env, process, thread, time::Duration};

fn spawn_daemon(info: &str) -> Result<(), Box<dyn std::error::Error>> {
    let exe_path = env::current_exe()?;
    
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let mut cmd = process::Command::new(exe_path);
        cmd.env("CLIPBOARD_DAEMON", "1")
           .env("DYNAMIC_INFO", info) // 传递动态信息
           .stderr(process::Stdio::inherit())
           .process_group(0);
        
        cmd.spawn()?;
    }
    
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let mut cmd = process::Command::new(exe_path);
        cmd.env("CLIPBOARD_DAEMON", "1")
           .env("DYNAMIC_INFO", info) // 传递动态信息
           .stderr(process::Stdio::inherit())
           .creation_flags(0x08000000); // CREATE_NO_WINDOW
        
        cmd.spawn()?;
    }
    
    Ok(())
}

fn daemon_task(secret: &str, duation: u64) -> Result<(), Box<dyn std::error::Error>> {
    // 等待指定时间(秒)
    thread::sleep(Duration::from_secs(duation));
    
    let mut ctx = match Clipboard::new() {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("[守护进程] 剪贴板初始化失败: {}", e);
            return Ok(());
        }
    };
    
    let current_content = ctx.get_text().unwrap_or_else(|_| String::new());
    
    if current_content == secret {
        if let Err(e) = ctx.set_text("") {
            eprintln!("[守护进程] 清空剪贴板失败: {}", e);
        } else {
            println!("[守护进程] 剪贴板内容未更改，已清空");
        }
    } else {
        println!("[守护进程] 剪贴板已更改，无需操作");
    }
    
    Ok(())
}

pub fn copy_to_clipboard(secret: &str, duation: u64) -> Result<(), Box<dyn std::error::Error>> {
    // 检查是否作为守护进程运行
    if env::var("CLIPBOARD_DAEMON").is_ok() {
        // 守护进程逻辑 - 从环境变量读取重要信息
        let info = env::var("DYNAMIC_INFO")
            .map_err(|_| "无法获取DYNAMIC_INFO环境变量")?;
        daemon_task(&info, duation)
    } else {
        // 复制到剪贴板
        let mut ctx = Clipboard::new()?;
        ctx.set_text(secret)?;
        // 主进程逻辑 - 启动守护进程并传递信息
        spawn_daemon(&secret)?;
        Ok(())
    }
}