@echo off
setlocal EnableDelayedExpansion

:: 设置颜色
color 0A

:: 检查Python是否安装
echo 正在检查Python环境...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [错误] 未检测到Python环境，请先安装Python
    pause
    exit /b 1
)

:: 检查必要的Python包
echo 正在检查必要的包...
python -c "import PyInstaller" >nul 2>&1
if %errorlevel% neq 0 (
    echo 正在安装PyInstaller...
    pip install pyinstaller
    if %errorlevel% neq 0 (
        color 0C
        echo [错误] PyInstaller安装失败
        pause
        exit /b 1
    )
)

:: 检查Inno Setup是否安装
echo 正在检查Inno Setup...
if not exist "F:\Inno Setup 6\ISCC.exe" (
    color 0C
    echo [错误] 未检测到Inno Setup 6，请先安装
    echo 下载地址: https://jrsoftware.org/isdl.php
    pause
    exit /b 1
)

:: 检查必要文件
echo 正在检查项目文件...
if not exist "src\stream_capture.py" (
    color 0C
    echo [错误] 未找到 src\stream_capture.py
    pause
    exit /b 1
)

if not exist "setup.iss" (
    color 0C
    echo [错误] 未找到 setup.iss
    pause
    exit /b 1
)

if not exist "app.ico" (
    color 0C
    echo [错误] 未找到 app.ico
    pause
    exit /b 1
)

:: 清理旧的构建文件
echo 正在清理旧文件...
if exist "dist" rd /s /q "dist"
if exist "build" rd /s /q "build"
if exist "installer" rd /s /q "installer"

:: 创建输出目录
mkdir installer

:: 构建Python程序
echo.
echo [第1步/2] 正在构建Python程序...
python build.py
if %errorlevel% neq 0 (
    color 0C
    echo [错误] Python程序构建失败
    pause
    exit /b 1
)

:: 创建安装程序
echo.
echo [第2步/2] 正在创建安装程序...
"F:\Inno Setup 6\ISCC.exe" setup.iss
if %errorlevel% neq 0 (
    color 0C
    echo [错误] 安装程序创建失败
    pause
    exit /b 1
)

:: 完成
color 0A
echo.
echo 构建完成！
echo 安装程序位于 installer 目录下
echo.
pause