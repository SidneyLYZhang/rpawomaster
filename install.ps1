<#
.SYNOPSIS
    一键安装/注册 rpawomaster 到当前用户 PATH。
.DESCRIPTION
    1. 检查当前目录是否存在 rpawomaster_v0.1.8.exe
       - 若不存在，询问用户是“下载”还是“手动指定目录”。
    2. 若选择下载，则从固定 URL 下载到当前目录，并把当前目录加入 PATH。
    3. 若选择指定目录，则把该目录加入 PATH。
    4. 提示用户重新打开终端，验证 `rpawomaster --help`。
.NOTES
    File Name : install.ps1
    Author    : SidneyZhang <zly@lyzhang.me>
#>

# 参数可在此处修改
$DownloadUrl   = "https://github.com/SidneyLYZhang/rpawomaster/releases/download/v0.1.8/rpawomaster_v0.1.8.exe"
$ExeName       = "rpawomaster.exe"

#-----------------------------------------------------------
function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

#-----------------------------------------------------------
function Add-ToUserPath {
    param(
        [string]$Folder
    )
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")

    # 避免重复添加
    $paths = $currentPath -split [IO.Path]::PathSeparator
    if ($paths -contains $Folder) {
        Write-Host "路径已存在于用户 PATH，跳过添加。" -ForegroundColor Yellow
        return
    }

    $newPath = $currentPath + [IO.Path]::PathSeparator + $Folder
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")

    Write-Host "已将 `"$Folder`" 添加到用户 PATH。" -ForegroundColor Green
}

#-----------------------------------------------------------
function Start-Download {
    param(
        [string]$Url,
        [string]$Dest
    )
    try {
        Write-Host "正在下载 $Url ..."
        # 使用 BITS（兼容性好、支持断点续传）
        Start-BitsTransfer -Source $Url -Destination $Dest -ErrorAction Stop
        Write-Host "下载完成：$Dest" -ForegroundColor Green
    }
    catch {
        Write-Host "下载失败：$_" -ForegroundColor Red
        exit 1
    }
}

#-----------------------------------------------------------
# 主流程
#-----------------------------------------------------------
$currentDir = (Get-Item -Path ".\").FullName
$exePath    = Join-Path $currentDir $ExeName

if -not (Test-Path $exePath) {
    $choice = ""
    while ($choice -notin "1","2","3") {
        Write-Host "`n程序不在当前目录，请选择操作：" -ForegroundColor Yellow
        Write-Host "1) 从网络下载到当前目录"
        Write-Host "2) 用户指定程序所在目录"
        Write-Host "3) 使用WinGet从网络安装"
        $choice = Read-Host "请输入 1 、 2 或 3 "
    }
    
    switch ($choice) {
        "1" {
            Start-Download -Url $DownloadUrl -Dest $exePath
        }
        "2" {
            $folder = ""
            while (-not (Test-Path -LiteralPath $folder -PathType Container)) {
                $folder = Read-Host "请输入程序所在的完整目录路径"
                if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
                    Write-Host "目录不存在，请重试！" -ForegroundColor Red
                }
            }
        }
        "3" {
            Write-Host "目前在不支持……"
            exit 1
        }
    }
}

$choice = ""
while ($choice -notin "1","2","3") {
    Write-Host "`n选择安装位置：" -ForegroundColor Yellow
    Write-Host "1) 当前目录"
    Write-Host "2) 文件所在目录"
    Write-Host "3) 其他指定目录"
    $choice = Read-Host "请输入 1 、 2 或 3 "
}

switch ($choice) {
    "1" {

            
        Add-ToUserPath -Folder $currentDir
    }
    "2" {
        $folder = ""
        while (-not (Test-Path -LiteralPath $folder -PathType Container)) {
            $folder = Read-Host "请输入 rpawo.exe 所在的完整目录路径"
            if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
                Write-Host "目录不存在，请重试！" -ForegroundColor Red
            }
        }
        Add-ToUserPath -Folder $folder
    }
}

#-----------------------------------------------------------
Write-Host "`n安装完成！" -ForegroundColor Green
Write-Host "请重新打开 PowerShell / CMD，然后执行以下命令验证：" -ForegroundColor Cyan
Write-Host "    rpawomaster --help"