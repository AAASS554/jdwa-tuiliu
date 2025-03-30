import PyInstaller.__main__
import sys
import os

# 获取当前目录
current_dir = os.path.dirname(os.path.abspath(__file__))

PyInstaller.__main__.run([
    'src/stream_capture.py',  # 修改为正确的源文件路径
    '--name=抖音直播推流码捕获工具',  # 程序名称
    '--windowed',  # 无控制台窗口
    '--icon=app.ico',  # 程序图标
    '--add-data=app.ico;.',  # 添加资源文件
    '--hidden-import=scapy.layers.http',  # 添加隐式导入
    '--hidden-import=netifaces',
    '--hidden-import=pymysql',
    '--hidden-import=cryptography',
    '--hidden-import=PIL',
    '--hidden-import=aliyunsdkcore',
    '--hidden-import=tkinter',
    '--hidden-import=email.mime.text',
    '--hidden-import=email.header',
    '--hidden-import=smtplib',
    '--hidden-import=uuid',
    # 添加 Qt 相关的排除
    '--exclude-module=PyQt5',
    '--exclude-module=PyQt6',
    '--exclude-module=PySide2',
    '--exclude-module=PySide6',
    '--clean',  # 清理临时文件
    '--noupx',  # 不使用UPX压缩
    '--noconfirm',  # 覆盖输出目录
    f'--distpath={os.path.join(current_dir, "dist")}',  # 输出目录
    f'--workpath={os.path.join(current_dir, "build")}',  # 工作目录
    f'--specpath={current_dir}'  # spec文件目录
]) 