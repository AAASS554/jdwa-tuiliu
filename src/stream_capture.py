from scapy.all import *
from scapy.layers.http import *
import re
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import json
from datetime import datetime, timedelta
import sys
import os
import netifaces  # 需要安装：pip install netifaces
import requests
import pymysql
import hashlib
from cryptography.fernet import Fernet
import base64
import time
import random
from PIL import Image, ImageTk
import webbrowser
import logging
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from smtplib import SMTP_SSL
import uuid

class DBConfig:
    def __init__(self):
        # 加密后的配置（使用下面的encrypt_config()生成）
        self._encoded = "WVcxaGVtbHVaMjg5TURBd01EQXdNQT09fHwxTWpFdU16Y3VOakkxTGpJME53PT18fGMzUnlaV0Z0WDJOaGNIUjFjbVU9fHxUR3BvTURNd09ERTFYekU9fHxjM1J5WldGdFgyTmhjSFIxY21VPXx8TXpNd05nPT0="
        
        # 解密配置
        self.DB_CONFIG = self._decrypt_config()
        
        # 用于加密的密钥
        self.SECRET_KEY = "dj8K9#mP$2@qL5nX"  # 使用复杂的随机字符串
    
    def _decrypt_config(self):
        try:
            # 解码base64
            decoded = base64.b64decode(self._encoded).decode()
            # 分割配置项
            items = decoded.split("||")
            # 解码每一项
            config = {
                'host': base64.b64decode(items[1]).decode(),
                'user': base64.b64decode(items[2]).decode(),
                'password': base64.b64decode(items[3]).decode(),
                'database': base64.b64decode(items[4]).decode(),
                'port': int(base64.b64decode(items[5]).decode())
            }
            return config
        except:
            # 如果解密失败，返回默认配置
            return {
                'host': '',
                'user': 'stream_capture',
                'password': '',
                'database': 'stream_capture',
                'port': 3306
            }

    @staticmethod
    def encrypt_config():
        """用于生成加密配置字符串"""
        config = {
            'host': '',
            'user': 'stream_capture',
            'password': '',
            'database': 'stream_capture',
            'port': 3306
        }
        
        # 编码每一项
        encoded_items = [
            base64.b64encode("magic".encode()).decode(),
            base64.b64encode(config['host'].encode()).decode(),
            base64.b64encode(config['user'].encode()).decode(),
            base64.b64encode(config['password'].encode()).decode(),
            base64.b64encode(config['database'].encode()).decode(),
            base64.b64encode(str(config['port']).encode()).decode()
        ]
        
        # 合并并再次编码
        final = "||".join(encoded_items)
        return base64.b64encode(final.encode()).decode()

# 创建全局配置实例
config = DBConfig()

class AppStyle:
    """统一的应用程序样式"""
    
    # 颜色方案
    COLORS = {
        'primary': '#4299E1',      # 主色调（按钮、强调色）
        'secondary': '#63B3ED',    # 次要色调（悬停效果）
        'bg': '#F7FAFC',           # 背景色
        'fg': '#2D3748',          # 文字颜色
        'border': '#E2E8F0',      # 边框颜色
        'error': '#FC8181',       # 错误提示
        'success': '#68D391',     # 成功提示
        'warning': '#F6E05E',     # 警告提示
        'disabled': '#CBD5E0'     # 禁用状态
    }
    
    # 字体设置
    FONTS = {
        'title': ('Microsoft YaHei UI', 20, 'bold'),
        'subtitle': ('Microsoft YaHei UI', 16, 'bold'),
        'body': ('Microsoft YaHei UI', 10),
        'button': ('Microsoft YaHei UI', 9),
        'small': ('Microsoft YaHei UI', 8)
    }
    
    # 布局参数
    LAYOUT = {
        'padding': 20,
        'button_width': 15,
        'entry_width': 30,
        'small_button_width': 10
    }
    
    @classmethod
    def setup_styles(cls):
        """配置ttk样式"""
        style = ttk.Style()
        
        # 配置基本样式
        style.configure('.',
            background=cls.COLORS['bg'],
            foreground=cls.COLORS['fg'],
            font=cls.FONTS['body']
        )
        
        # 主按钮样式
        style.configure('Primary.TButton',
            background=cls.COLORS['primary'],
            foreground='white',
            padding=8,
            font=cls.FONTS['button']
        )
        
        # 次要按钮样式
        style.configure('Secondary.TButton',
            background=cls.COLORS['secondary'],
            padding=6,
            font=cls.FONTS['button']
        )
        
        # 输入框样式
        style.configure('TEntry',
            padding=5,
            fieldbackground='white'
        )
        
        # 标签样式
        style.configure('TLabel',
            background=cls.COLORS['bg'],
            font=cls.FONTS['body']
        )
        
        # 进度条样式
        style.configure('Horizontal.TProgressbar',
            background=cls.COLORS['primary'],
            troughcolor=cls.COLORS['border']
        )
        
        # 红色进度条
        style.configure('red.Horizontal.TProgressbar',
            background=cls.COLORS['error']
        )
        
        # 黄色进度条
        style.configure('yellow.Horizontal.TProgressbar',
            background=cls.COLORS['warning']
        )
        
        # 绿色进度条
        style.configure('green.Horizontal.TProgressbar',
            background=cls.COLORS['success']
        )

class LoginWindow:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("登录 - 抖音直播推流码捕获工具")
        self.window.geometry("400x500")
        
        # 定义配色方案
        self.colors = {
            'bg': '#F0F4F8',
            'fg': '#2D3748',
            'secondary_bg': '#E2E8F0',
            'accent': '#4299E1',
            'hover': '#63B3ED',
            'border': '#CBD5E0'
        }
        
        self.window.configure(bg=self.colors['bg'])
        self.db = DatabaseManager()
        
        # 初始化变量
        self.remember_var = tk.BooleanVar(value=True)  # 默认勾选记住密码
        self.auto_login_var = tk.BooleanVar(value=False)  # 默认不自动登录
        self.login_attempts = {}  # 记录登录失败次数
        self.login_cooldown = {}  # 记录冷却时间
        
        # 先设置UI
        self.setup_ui()
        
        # 添加配置文件路径
        self.config_dir = os.path.join(os.path.expanduser('~'), '.stream_capture')
        self.config_file = os.path.join(self.config_dir, 'config.json')
        self.key_file = os.path.join(self.config_dir, 'key')
        
        # 确保配置目录存在
        os.makedirs(self.config_dir, exist_ok=True)
        
        # 初始化或加载加密密钥
        self.init_encryption()
        
        # 最后加载保存的账号密码
        self.window.after(100, self.load_saved_credentials)
        
    def init_encryption(self):
        """初始化或加载加密密钥"""
        try:
            if os.path.exists(self.key_file):
                # 如果密钥文件存在，加载它
                with open(self.key_file, 'rb') as f:
                    self.encryption_key = f.read()
            else:
                # 如果密钥文件不存在，生成新密钥
                self.encryption_key = Fernet.generate_key()
                with open(self.key_file, 'wb') as f:
                    f.write(self.encryption_key)
            
            # 创建 Fernet 实例
            self.cipher_suite = Fernet(self.encryption_key)
            
        except Exception as e:
            logging.error(f"初始化加密失败: {str(e)}")
            # 如果出错，重新生成密钥
            self.encryption_key = Fernet.generate_key()
            self.cipher_suite = Fernet(self.encryption_key)
            try:
                with open(self.key_file, 'wb') as f:
                    f.write(self.encryption_key)
            except Exception as e:
                logging.error(f"保存加密密钥失败: {str(e)}")

    def setup_ui(self):
        # 应用样式
        AppStyle.setup_styles()
        
        # 设置窗口背景色
        self.window.configure(bg=AppStyle.COLORS['bg'])
        
        # 创建主框架
        main_frame = ttk.Frame(self.window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=AppStyle.LAYOUT['padding'], 
                       pady=AppStyle.LAYOUT['padding'])
        
        # Logo或标题
        ttk.Label(main_frame, 
                 text="抖音直播推流码捕获工具", 
                 font=AppStyle.FONTS['title']).pack(pady=20)
        
        # 用户名
        ttk.Label(main_frame, text="用户名:", 
                 font=AppStyle.FONTS['body']).pack(anchor='w', pady=(10,5))
        self.username_entry = ttk.Entry(main_frame, 
                                      width=AppStyle.LAYOUT['entry_width'])
        self.username_entry.pack(fill=tk.X)
        
        # 密码
        ttk.Label(main_frame, text="密码:", 
                 font=AppStyle.FONTS['body']).pack(anchor='w', pady=(10,5))
        self.password_entry = ttk.Entry(main_frame, 
                                      width=AppStyle.LAYOUT['entry_width'], 
                                      show="*")
        self.password_entry.pack(fill=tk.X)
        
        # 选项框架
        options_frame = ttk.Frame(main_frame)
        options_frame.pack(fill=tk.X, pady=10)
        
        # 记住密码选项
        ttk.Checkbutton(options_frame, 
                       text="记住账号",
                       variable=self.remember_var).pack(side=tk.LEFT, padx=5)
        
        # 自动登录选项
        ttk.Checkbutton(options_frame, 
                       text="自动登录",
                       variable=self.auto_login_var).pack(side=tk.LEFT, padx=5)
        
        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=20)
        
        # 登录按钮
        ttk.Button(button_frame, 
                  text="登录",
                  style='Primary.TButton',
                  width=AppStyle.LAYOUT['button_width'],
                  command=self.do_login).pack(pady=5)
        
        # 注册按钮
        ttk.Button(button_frame,
                  text="注册新账号",
                  style='Secondary.TButton',
                  width=AppStyle.LAYOUT['button_width'],
                  command=self.show_register).pack(pady=5)
        
        # 状态标签
        self.status_label = ttk.Label(main_frame, 
                                    font=AppStyle.FONTS['small'],
                                    foreground=AppStyle.COLORS['error'])
        self.status_label.pack(pady=10)
        
        # 如果有保存的凭据且设置了自动登录，直接登录
        if hasattr(self, 'saved_username') and hasattr(self, 'saved_password'):
            config = self.load_config()
            if config.get('auto_login'):
                self.window.after(500, self.do_login)
        
    def do_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        # 检查是否在冷却中
        if username in self.login_cooldown:
            cooldown_until = self.login_cooldown[username]
            if datetime.now() < cooldown_until:
                remaining = int((cooldown_until - datetime.now()).total_seconds())
                self.status_label.config(text=f"请等待{remaining}秒后再试")
                return
            else:
                del self.login_cooldown[username]
                if username in self.login_attempts:
                    del self.login_attempts[username]
        
        if not username or not password:
            self.status_label.config(text="用户名和密码不能为空")
            return
        
        result = self.db.login(username, password)
        if result['success']:
            # 登录成功，重置失败次数
            if username in self.login_attempts:
                del self.login_attempts[username]
            
            # 记住密码处理
            if self.remember_var.get():
                self.save_credentials()
            else:
                self.clear_credentials()
            
            self.window.destroy()
            app = StreamCapture(result['user_id'], result['vip_expire'])
            app.run()
        else:
            # 记录失败次数
            self.login_attempts[username] = self.login_attempts.get(username, 0) + 1
            
            # 检查失败次数
            if self.login_attempts[username] >= 5:
                # 设置5分钟冷却时间
                self.login_cooldown[username] = datetime.now() + timedelta(minutes=5)
                self.status_label.config(text="登录失败次数过多，请5分钟后再试")
            else:
                remaining = 5 - self.login_attempts[username]
                self.status_label.config(text=f"用户名或密码错误，还剩{remaining}次机会")
            
    def show_register(self):
        def send_verification_code():
            email = email_entry.get()
            if not email:
                status_label.config(text="请输入QQ邮箱")
                return
                
            if not email.endswith('@qq.com'):
                status_label.config(text="请使用QQ邮箱")
                return
                
            # 发送验证码
            result = email_verifier.send_code(email)
            if result['success']:
                # 发送成功
                status_label.config(text=result['message'])
                # 禁用发送按钮60秒
                send_code_button.config(state='disabled')
                countdown(60)
            else:
                # 发送失败
                status_label.config(text=result['message'])
                # 3秒后清除错误信息
                register_window.after(3000, lambda: status_label.config(text=""))
        
        def countdown(seconds):
            if seconds > 0:
                send_code_button.config(text=f"重新发送({seconds})")
                register_window.after(1000, lambda: countdown(seconds-1))
            else:
                send_code_button.config(text="发送验证码", state='normal')
        
        def do_register():
            username = username_entry.get()
            password = password_entry.get()
            confirm_pwd = confirm_pwd_entry.get()
            email = email_entry.get()
            code = code_entry.get()
            
            if not all([username, password, confirm_pwd, email, code]):
                status_label.config(text="请填写所有信息")
                return
                
            if password != confirm_pwd:
                status_label.config(text="两次输入的密码不一致")
                return
                
            if not email.endswith('@qq.com'):
                status_label.config(text="请使用QQ邮箱")
                return
                
            # 验证验证码
            is_valid, message = email_verifier.verify_code(email, code)
            if not is_valid:
                status_label.config(text=message)
                return
                
            # 注册
            success, message = self.db.register(username, password, email)
            if success:
                messagebox.showinfo("注册成功", message)
                register_window.destroy()  # 关闭注册窗口
                # 自动填充用户名和密码
                self.username_entry.delete(0, tk.END)
                self.username_entry.insert(0, username)
                self.password_entry.delete(0, tk.END)
                self.password_entry.insert(0, password)
            else:
                status_label.config(text=message)
        
        # 创建注册窗口
        register_window = tk.Toplevel(self.window)
        register_window.title("注册 - 抖音直播推流码捕获工具")
        register_window.geometry("400x600")
        register_window.configure(bg=self.colors['bg'])
        
        # 创建邮箱验证实例
        email_verifier = EmailVerification(self.db)
        
        # 创建主框架
        main_frame = ttk.Frame(register_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 用户名
        ttk.Label(main_frame, text="用户名:").pack(anchor='w')
        username_entry = ttk.Entry(main_frame)
        username_entry.pack(fill=tk.X, pady=(0,10))
        
        # 密码
        ttk.Label(main_frame, text="密码:").pack(anchor='w')
        password_entry = ttk.Entry(main_frame, show="*")
        password_entry.pack(fill=tk.X, pady=(0,10))
        
        # 确认密码
        ttk.Label(main_frame, text="确认密码:").pack(anchor='w')
        confirm_pwd_entry = ttk.Entry(main_frame, show="*")
        confirm_pwd_entry.pack(fill=tk.X, pady=(0,10))
        
        # QQ邮箱
        ttk.Label(main_frame, text="QQ邮箱:").pack(anchor='w')
        email_entry = ttk.Entry(main_frame)
        email_entry.pack(fill=tk.X, pady=(0,10))
        
        # 验证码
        code_frame = ttk.Frame(main_frame)
        code_frame.pack(fill=tk.X, pady=(0,10))
        
        code_entry = ttk.Entry(code_frame)
        code_entry.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0,5))
        
        send_code_button = ttk.Button(code_frame, 
                                     text="发送验证码",
                                     command=send_verification_code)
        send_code_button.pack(side=tk.RIGHT)
        
        # 状态标签
        status_label = ttk.Label(main_frame, foreground='red')
        status_label.pack(pady=10)
        
        # 注册按钮
        ttk.Button(main_frame,
                   text="注册",
                   style='Primary.TButton',
                   command=do_register).pack(pady=10)
        
        # 返回登录按钮
        ttk.Button(main_frame,
                   text="返回登录",
                   style='Secondary.TButton',
                   command=register_window.destroy).pack(pady=5)

    def run(self):
        self.window.mainloop()

    def load_saved_credentials(self):
        """加载保存的账号密码"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if data.get('remember', False):
                        username = data.get('username', '')
                        if username:
                            self.username_entry.delete(0, tk.END)
                            self.username_entry.insert(0, username)
                        
                        if data.get('password'):
                            try:
                                decrypted_pwd = self.decrypt_password(data['password'])
                                if decrypted_pwd:
                                    self.password_entry.delete(0, tk.END)
                                    self.password_entry.insert(0, decrypted_pwd)
                                    self.remember_var.set(1)
                                    if data.get('auto_login'):
                                        self.auto_login_var.set(1)
                            except Exception as e:
                                logging.error(f"密码解密失败: {str(e)}")
                                self.clear_credentials()
        except Exception as e:
            logging.error(f"加载账号密码失败: {str(e)}")
            self.clear_credentials()

    def clear_credentials(self):
        """清除保存的账号密码"""
        try:
            # 清空输入框
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.remember_var.set(0)
            self.auto_login_var.set(0)
            
            # 删除文件时先检查是否存在
            if os.path.exists(self.config_file):
                try:
                    os.remove(self.config_file)
                except PermissionError:
                    # 如果文件被占用，等待一会再试
                    self.window.after(100, self.clear_credentials)
                    return
                    
            if os.path.exists(self.key_file):
                try:
                    os.remove(self.key_file)
                except PermissionError:
                    # 如果文件被占用，等待一会再试
                    self.window.after(100, self.clear_credentials)
                    return
                    
            # 如果目录为空，删除目录
            if os.path.exists(self.config_dir) and not os.listdir(self.config_dir):
                try:
                    os.rmdir(self.config_dir)
                except (PermissionError, OSError):
                    pass
        except Exception as e:
            logging.error(f"清除账号密码失败: {str(e)}")

    def save_credentials(self):
        """保存账号密码"""
        try:
            if self.remember_var.get():
                password = self.password_entry.get()
                if not password:
                    return
                    
                # 加密密码
                encrypted = self.encrypt_password(password)
                if not encrypted:
                    return
                
                data = {
                    'remember': True,
                    'username': self.username_entry.get(),
                    'password': encrypted,
                    'auto_login': self.auto_login_var.get()
                }
                
                # 保存配置
                try:
                    with open(self.config_file, 'w', encoding='utf-8') as f:
                        json.dump(data, f, ensure_ascii=False)
                except PermissionError:
                    # 如果文件被占用，等待一会再试
                    self.window.after(100, self.save_credentials)
            else:
                self.clear_credentials()
        except Exception as e:
            logging.error(f"保存账号密码失败: {str(e)}")

    def encrypt_password(self, password):
        """加密密码"""
        try:
            if not password:
                return None
            encrypted = self.cipher_suite.encrypt(password.encode())
            return base64.urlsafe_b64encode(encrypted).decode()
        except Exception as e:
            logging.error(f"密码加密失败: {str(e)}")
            return None
    
    def decrypt_password(self, encrypted):
        """解密密码"""
        try:
            if not encrypted:
                return None
            encrypted_bytes = base64.urlsafe_b64decode(encrypted.encode())
            decrypted = self.cipher_suite.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            logging.error(f"密码解密失败: {str(e)}")
            return None

class StreamCapture:
    def __init__(self, user_id, vip_expire):
        self.user_id = user_id
        self.vip_expire = vip_expire
        self.db = DatabaseManager()
        
        self.window = tk.Tk()
        self.window.title("抖音直播推流码捕获工具")
        self.window.geometry("800x600")
        
        # 定义配色方案
        self.colors = {
            'bg': '#F0F4F8',
            'fg': '#2D3748',
            'secondary_bg': '#E2E8F0',
            'accent': '#4299E1',
            'hover': '#63B3ED',
            'border': '#CBD5E0'
        }
        
        # 初始化捕获相关的属性
        self.captured_streams = set()  # 已捕获的推流地址集合
        self.is_capturing = False     # 捕获状态
        self.capture_thread = None    # 捕获线程
        self.current_server = None    # 当前RTMP服务器
        
        # 配置文件路径
        if os.name == 'nt':  # Windows系统
            self.config_file = os.path.join(os.getenv('APPDATA'), '.stream_capture_config')
        else:  # Linux/Unix系统
            self.config_file = os.path.join(os.path.expanduser('~'), '.stream_capture_config')
        
        self.window.configure(bg=self.colors['bg'])
        self.setup_menu()
        self.setup_ui()
        
        # 配置进度条样式
        style = ttk.Style()
        style.configure("red.Horizontal.TProgressbar", 
                       troughcolor='#F0F4F8', 
                       background='#E53E3E')
        style.configure("yellow.Horizontal.TProgressbar", 
                       troughcolor='#F0F4F8', 
                       background='#ECC94B')
        style.configure("green.Horizontal.TProgressbar", 
                       troughcolor='#F0F4F8', 
                       background='#48BB78')
        
        # 启动VIP检查
        self.check_vip_status()
        
        # 启动活跃状态更新
        self.start_active_timer()
        
        # 启动登录状态检查
        self.check_login_status()
        
        # 保存上次活跃时间
        self._last_active = datetime.now()
        
    def setup_menu(self):
        menubar = tk.Menu(self.window)
        self.window.config(menu=menubar)
        
        # 用户菜单
        user_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="用户", menu=user_menu)
        
        # 添加用户信息和VIP状态标签
        self.vip_label = tk.StringVar(value="正在加载VIP状态...")
        user_menu.add_command(label=self.vip_label.get(), state='disabled')
        
        # 添加VIP进度条
        self.progress_frame = ttk.Frame(self.window)
        self.progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.progress_label = ttk.Label(self.progress_frame, text="VIP状态")
        self.progress_label.pack(side=tk.LEFT, padx=5)
        
        self.progress_bar = ttk.Progressbar(self.progress_frame, length=200, mode='determinate')
        self.progress_bar.pack(side=tk.LEFT, padx=5)
        
        self.days_label = ttk.Label(self.progress_frame, text="")
        self.days_label.pack(side=tk.LEFT, padx=5)
        
        # 其他菜单项...
        user_menu.add_command(label="续费VIP", command=self.show_purchase_window)
        user_menu.add_separator()
        user_menu.add_command(label="退出登录", command=self.logout)
        
        # 帮助菜单
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="帮助", menu=help_menu)
        help_menu.add_command(label="使用说明", command=self.show_help_window)
        help_menu.add_command(label="检查更新", command=self.check_update)
        help_menu.add_command(label="问题反馈", command=self.show_feedback_window)
        help_menu.add_separator()
        help_menu.add_command(label="联系作者", command=lambda: webbrowser.open('weixin://dl/chat?Hatebetray_'))
        
        # 启动VIP状态更新定时器
        self.update_vip_status()
        
    def logout(self):
        """退出登录"""
        try:
            # 停止所有正在进行的捕获
            if hasattr(self, 'capture_thread') and self.capture_thread.is_alive():
                self.stop_capture()
            
            # 保存当前设置
            self.save_settings()
            
            # 立即清除设备ID
            self.db.logout(self.user_id)
            
            # 关闭数据库连接
            if hasattr(self, 'db'):
                del self.db
            
            # 关闭当前窗口
            self.window.destroy()
            
            # 重新启动登录窗口
            login = LoginWindow()
            login.run()
            
        except Exception as e:
            logging.error(f"退出登录异常: {str(e)}")
            # 如果正常退出失败，强制退出
            try:
                self.window.destroy()
            except:
                pass
            sys.exit(1)

    def setup_ui(self):
        # 主框架
        main_frame = ttk.Frame(self.window, style='Main.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 控制区域（使用圆角边框）
        control_frame = tk.Frame(main_frame, bg=self.colors['secondary_bg'])
        control_frame.pack(pady=10, padx=10, fill=tk.X)
        
        # 添加圆角效果
        def create_rounded_frame(widget):
            widget.update_idletasks()
            width = widget.winfo_width()
            height = widget.winfo_height()
            mask = tk.PhotoImage(width=width, height=height)
            mask.put(('black',), to=(0, 0, width, height))
            widget._mask = mask  # 保持引用
            widget.configure(highlightthickness=0, bd=0)
        
        control_frame.bind('<Configure>', lambda e: create_rounded_frame(control_frame))
        
        # 网卡选择
        ttk.Label(control_frame, text="网卡:", style='Custom.TLabel').pack(side=tk.LEFT, padx=10, pady=10)
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(control_frame, 
            textvariable=self.iface_var, 
            width=30,
            style='Custom.TCombobox'
        )
        
        # 设置网卡列表
        self.interfaces = self.get_interfaces()
        if self.interfaces:
            iface_descriptions = [f"{i['description']} ({i['ip']})" for i in self.interfaces]
            self.iface_combo['values'] = iface_descriptions
            
            # 尝试加载上次选择的网卡
            last_iface = self.load_last_interface()
            if last_iface in iface_descriptions:
                self.iface_combo.set(last_iface)
            else:
                self.iface_combo.current(0)
            
            self.log_result(f"已选择网卡: {self.iface_combo.get()}")
        else:
            self.iface_combo['values'] = ['未找到可用网卡']
            self.iface_combo.current(0)
            self.log_result("警告: 未找到可用网卡")
        
        self.iface_combo.pack(side=tk.LEFT, padx=10, pady=10)
        
        # 添加网卡选择变更事件
        self.iface_combo.bind('<<ComboboxSelected>>', self.on_interface_changed)
        
        # 按钮
        self.start_btn = ttk.Button(control_frame, 
            text="开始捕获",
            style='Custom.TButton',
            command=self.toggle_capture
        )
        self.start_btn.pack(side=tk.LEFT, padx=10, pady=10)
        
        self.clear_btn = ttk.Button(control_frame,
            text="清除记录",
            style='Custom.TButton',
            command=self.clear_results
        )
        self.clear_btn.pack(side=tk.LEFT, padx=10, pady=10)
        
        # 状态标签
        self.status_label = ttk.Label(control_frame,
            text="就绪",
            style='Custom.TLabel'
        )
        self.status_label.pack(side=tk.RIGHT, padx=10, pady=10)
        
        # 结果显示区域
        result_frame = ttk.LabelFrame(main_frame,
            text="捕获结果",
            style='Custom.TLabelframe'
        )
        result_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        
        # 自定义文本框样式
        self.result_text = tk.Text(result_frame,
            wrap=tk.WORD,
            bg=self.colors['secondary_bg'],
            fg=self.colors['fg'],
            insertbackground=self.colors['fg'],
            selectbackground=self.colors['accent'],
            selectforeground='white',
            font=('Microsoft YaHei UI', 10),
            bd=0,
            padx=10,
            pady=10
        )
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 自定义滚动条
        scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.result_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text.configure(yscrollcommand=scrollbar.set)
        
    def get_selected_interface(self):
        """获取选中的网卡名称"""
        if not self.interfaces:
            raise Exception("没有可用的网卡")
        try:
            idx = self.iface_combo.current()
            selected_iface = self.interfaces[idx]
            self.log_result(f"选择网卡: {selected_iface['description']} ({selected_iface['ip']})")
            return selected_iface['name']
        except Exception as e:
            self.log_result(f"获取选中网卡失败: {str(e)}")
            # 如果出错，尝试使用默认网卡
            return conf.iface.name
        
    def clear_results(self):
        self.result_text.delete(1.0, tk.END)
        self.captured_streams.clear()  # 清除已捕获的记录
        
    def toggle_capture(self):
        if not self.is_capturing:
            self.start_capture()
        else:
            self.stop_capture()
            
    def start_capture(self):
        """开始捕获前检查VIP状态"""
        if not self.check_vip_status():
            messagebox.showwarning("提示", "您的VIP已过期，请续费后使用")
            return
        
        try:
            self.is_capturing = True
            self.start_btn.configure(text="停止捕获")
            self.status_label.configure(text="正在捕获...")
            self.capture_thread = threading.Thread(target=self.capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
        except Exception as e:
            messagebox.showerror("错误", f"启动捕获失败：{str(e)}")
            self.stop_capture()
        
    def stop_capture(self):
        self.is_capturing = False
        self.start_btn.configure(text="开始捕获")
        self.status_label.configure(text="已停止")
        

            
    def log_result(self, message):
        def _update():
            self.result_text.insert(tk.END,
                f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]\n",
                'timestamp'
            )
            self.result_text.insert(tk.END, f"{message}\n", 'message')
            self.result_text.insert(tk.END, "----------------------------------------\n", 'separator')
            
            # 更新文本标签颜色
            self.result_text.tag_configure('timestamp', foreground='#718096')  # 柔和的灰蓝色
            self.result_text.tag_configure('message', foreground=self.colors['fg'])
            self.result_text.tag_configure('separator', foreground='#CBD5E0')  # 浅灰色分隔符
            
            self.result_text.see(tk.END)
        
        self.window.after(0, _update)
        
    def run(self):
        try:
            self.window.mainloop()
        except Exception as e:
            messagebox.showerror("错误", f"程序运行错误：{str(e)}")

    def load_last_interface(self):
        """加载上次选择的网卡"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    return config.get('last_interface', '')
        except Exception as e:
            self.log_result(f"加载配置文件失败: {str(e)}")
        return ''

    def save_last_interface(self, iface_description):
        """保存当前选择的网卡"""
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            
            # 尝试读取现有配置
            config = {}
            if os.path.exists(self.config_file):
                try:
                    with open(self.config_file, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                except:
                    pass  # 如果读取失败，使用空配置
            
            # 更新配置
            config['last_interface'] = iface_description
            
            # 保存配置
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except:
            # 尝试使用临时目录
            try:
                temp_config = os.path.join(os.getenv('TEMP'), '.stream_capture_config')
                with open(temp_config, 'w', encoding='utf-8') as f:
                    json.dump({'last_interface': iface_description}, f, ensure_ascii=False, indent=2)
                self.config_file = temp_config  # 更新配置文件路径
            except:
                pass  # 如果保存失败，静默处理

    def on_interface_changed(self, event):
        """网卡选择变更事件处理"""
        selected_iface = self.iface_combo.get()
        self.save_last_interface(selected_iface)
        self.log_result(f"已切换到网卡: {selected_iface}")

    def get_interfaces(self):
        """获取所有网卡信息"""
        interfaces = []
        try:
            # Windows系统
            if os.name == 'nt':
                from scapy.arch.windows import get_windows_if_list
                for iface in get_windows_if_list():
                    if iface.get('name') and iface.get('ips'):
                        interfaces.append({
                            'name': iface['name'],
                            'description': iface.get('description', iface['name']),
                            'ip': iface['ips'][0]  # 获取第一个IP地址
                        })
            # Linux/Unix系统
            else:
                for iface in get_if_list():
                    if iface != 'lo':  # 排除回环接口
                        try:
                            ip = get_if_addr(iface)
                            if ip != '0.0.0.0':
                                interfaces.append({
                                    'name': iface,
                                    'description': iface,
                                    'ip': ip
                                })
                        except:
                            continue
                        
            self.log_result(f"找到 {len(interfaces)} 个网卡接口")
            for iface in interfaces:
                self.log_result(f"网卡: {iface['description']} (IP: {iface['ip']})")
            
        except Exception as e:
            self.log_result(f"获取网卡列表时出错: {str(e)}")
        
        if not interfaces:
            # 如果没有找到网卡，添加默认网卡
            interfaces.append({
                'name': conf.iface.name,
                'description': f"默认网卡 ({conf.iface.name})",
                'ip': get_if_addr(conf.iface.name) or 'Unknown IP'
            })
        
        return interfaces

    def check_vip_status(self):
        """每分钟静默检查VIP状态"""
        try:
            result = self.db.check_vip(self.user_id)
            
            if result['success']:
                if result['is_valid']:
                    # VIP 有效，更新显示
                    self.vip_expire = result['expire_date']
                    days_left = result['days_left']
                    
                    # 更新进度条和标签
                    if days_left > 30:
                        self.progress_bar['style'] = 'green.Horizontal.TProgressbar'
                        self.progress_bar['value'] = 100
                        status = f"VIP有效，剩余 {days_left} 天"
                    else:
                        if days_left > 7:
                            self.progress_bar['style'] = 'yellow.Horizontal.TProgressbar'
                        else:
                            self.progress_bar['style'] = 'red.Horizontal.TProgressbar'
                        self.progress_bar['value'] = (days_left / 30) * 100
                        status = f"VIP有效，剩余 {days_left} 天"
                    
                    self.vip_label.set(status)
                    self.days_label.config(text=f"{days_left}天")
                    
                    # 检查是否即将到期
                    if 0 < days_left <= 3:
                        current_date = datetime.now().date()
                        last_warning_date = getattr(self, '_last_warning_date', None)
                        
                        if not last_warning_date or last_warning_date < current_date:
                            self._last_warning_date = current_date
                            if not hasattr(self, '_showed_warning'):
                                self._showed_warning = True
                                self.window.after(1000, lambda: messagebox.showwarning(
                                    "VIP到期提醒", 
                                    f"您的VIP将在{days_left}天后到期\n请及时续费以免影响使用"
                                ))
                    
                    return True  # VIP 有效，允许使用功能
                else:
                    # VIP 已过期
                    self.progress_bar['style'] = 'red.Horizontal.TProgressbar'
                    self.progress_bar['value'] = 0
                    self.vip_label.set("VIP已过期")
                    self.days_label.config(text="已过期")
                    
                    # 显示过期提示
                    if not hasattr(self, '_showed_expire_notice'):
                        self._showed_expire_notice = True
                        messagebox.showwarning(
                            "VIP已过期",
                            "您的VIP已过期，请续费后继续使用"
                        )
                    return False  # VIP 已过期，不允许使用功能
            else:
                logging.error(f"VIP检查失败: {result['message']}")
                return True  # 检查失败时默认允许使用
            
        except Exception as e:
            logging.error(f"VIP检查异常: {str(e)}")
            return True  # 出错时默认允许使用
        finally:
            # 一分钟后再次检查
            self.window.after(60000, self.check_vip_status)
    
    def show_purchase_window(self):
        """显示续费窗口"""
        purchase_window = tk.Toplevel(self.window)
        purchase_window.title("VIP续费")
        purchase_window.geometry("300x400")
        purchase_window.configure(bg=self.colors['bg'])
        
        # 创建主框架
        main_frame = ttk.Frame(purchase_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # VIP套餐信息
        packages = [
            {"name": "月卡", "price": "29.9", "days": 30},
            {"name": "季卡", "price": "79.9", "days": 90},
            {"name": "年卡", "price": "299", "days": 365},
            {"name": "永久", "price": "599", "days": 3650}
        ]
        
        ttk.Label(main_frame, 
                 text="VIP套餐",
                 font=('Microsoft YaHei UI', 12, 'bold')).pack(pady=10)
                 
        for pkg in packages:
            frame = ttk.Frame(main_frame)
            frame.pack(fill=tk.X, pady=5)
            ttk.Label(frame, text=f"{pkg['name']}").pack(side=tk.LEFT)
            ttk.Label(frame, text=f"¥{pkg['price']}").pack(side=tk.LEFT, padx=10)
        
        # 添加分隔线
        ttk.Separator(main_frame, orient='horizontal').pack(fill=tk.X, pady=20)
        
        # 联系方式
        ttk.Label(main_frame,
                 text="联系作者购买",
                 font=('Microsoft YaHei UI', 12, 'bold')).pack(pady=10)
                 
        ttk.Label(main_frame,
                 text="作者：记得晚安\n微信：Hatebetray_",
                 font=('Microsoft YaHei UI', 10)).pack(pady=5)
                 
        # 添加复制微信号按钮
        def copy_wechat():
            self.window.clipboard_clear()
            self.window.clipboard_append("Hatebetray_")
            messagebox.showinfo("提示", "微信号已复制到剪贴板")
            
        ttk.Button(main_frame,
                  text="复制微信号",
                  command=copy_wechat).pack(pady=10)

    def process_purchase(self, package):
        """处理购买请求"""
        # 直接显示联系方式
        messagebox.showinfo("购买提示", 
            f"请联系作者购买\n"
            f"作者：记得晚安\n"
            f"微信：Hatebetray_"
        )

    def check_update(self):
        """检查更新"""
        try:
            response = requests.get('https://api.yourserver.com/version')
            latest_version = response.json()['version']
            current_version = '1.0.0'  # 当前版本号
            
            if latest_version > current_version:
                if messagebox.askyesno("更新提示", 
                    f"发现新版本 {latest_version}\n是否立即更新？"):
                    webbrowser.open('https://yourserver.com/download')
        except:
            pass  # 静默处理更新检查失败

    def setup_logging(self):
        """设置日志"""
        log_dir = os.path.join(os.path.dirname(self.config_file), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, 
            f"capture_{datetime.now().strftime('%Y%m%d')}.log")
        
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def safe_connect(self):
        """安全的数据库连接"""
        retry_count = 3
        while retry_count > 0:
            try:
                if not self.conn or not self.conn.open:
                    self.connect()
                return True
            except Exception as e:
                retry_count -= 1
                time.sleep(1)
                if retry_count == 0:
                    raise e

    def show_feedback_window(self):
        """显示反馈窗口"""
        feedback_window = tk.Toplevel(self.window)
        feedback_window.title("问题反馈")
        feedback_window.geometry("400x300")
        feedback_window.configure(bg=self.colors['bg'])
        
        # 创建主框架
        main_frame = ttk.Frame(feedback_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        ttk.Label(main_frame, 
                 text="问题反馈",
                 font=('Microsoft YaHei UI', 12, 'bold')).pack(pady=10)
                 
        ttk.Label(main_frame, 
                 text="请描述您遇到的问题：").pack(pady=5)
                 
        text = tk.Text(main_frame, height=10)
        text.pack(pady=10, padx=10, fill=tk.BOTH)
        
        # 联系方式
        ttk.Label(main_frame, text="联系方式(选填):").pack(pady=5)
        contact_entry = ttk.Entry(main_frame)
        contact_entry.pack(pady=5, fill=tk.X)
        
        def submit_feedback():
            content = text.get(1.0, tk.END).strip()
            contact = contact_entry.get().strip()
            
            if not content:
                messagebox.showwarning("提示", "请输入反馈内容")
                return
            
            # 保存反馈到数据库
            try:
                cursor = self.db.conn.cursor()
                cursor.execute(
                    'INSERT INTO feedback (user_id, content, contact) VALUES (%s, %s, %s)',
                    (self.user_id, content, contact)
                )
                self.db.conn.commit()
                messagebox.showinfo("成功", "感谢您的反馈！我们会尽快处理")
                feedback_window.destroy()
            except:
                messagebox.showerror("错误", "提交失败，请稍后重试")
            finally:
                cursor.close()
        
        # 提交按钮
        ttk.Button(main_frame,
                  text="提交反馈",
                  command=submit_feedback).pack(pady=10)

    def show_help_window(self):
        """显示帮助信息"""
        help_window = tk.Toplevel(self.window)
        help_window.title("使用帮助")
        help_window.geometry("500x400")
        help_window.configure(bg=self.colors['bg'])
        
        # 创建主框架
        main_frame = ttk.Frame(help_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 帮助内容
        help_text = """
使用说明：

1. 选择正确的网卡
   - 确保选择连接抖音直播的网卡
   - 通常是您正在使用的网络连接

2. 开始捕获
   - 点击"开始捕获"按钮
   - 等待推流地址出现在下方
   
3. 复制推流地址
   - 双击推流地址可以复制
   - 地址可用于OBS等推流软件

4. 注意事项
   - 确保网络连接稳定
   - 推流地址有效期较短
   - 如遇问题请及时反馈

联系作者：记得晚安
微信：Hatebetray_
        """
        
        text = tk.Text(main_frame, wrap=tk.WORD, height=20)
        text.pack(fill=tk.BOTH, expand=True)
        text.insert('1.0', help_text)
        text.configure(state='disabled')  # 设为只读

    def update_vip_status(self):
        """更新VIP状态显示"""
        try:
            result = self.db.check_vip(self.user_id)
            
            if result['success']:
                expire_date = datetime.strptime(result['expire_date'], '%Y-%m-%d').date()
                days_left = (expire_date - datetime.now().date()).days
                
                # 调试日志
                logging.info(f"VIP状态更新 - 用户ID: {self.user_id}")
                logging.info(f"过期日期: {expire_date}")
                logging.info(f"剩余天数: {days_left}")
                
                if days_left >= 0:  # VIP 有效
                    # 更新进度条
                    if days_left > 30:
                        style = "green.Horizontal.TProgressbar"
                        progress = 100
                    elif days_left > 7:
                        style = "yellow.Horizontal.TProgressbar"
                        progress = days_left * 100 // 30
                    else:
                        style = "red.Horizontal.TProgressbar"
                        progress = days_left * 100 // 7
                    
                    self.progress_bar.configure(style=style)
                    self.progress_bar['value'] = progress
                    
                    # 更新标签
                    self.vip_label.set(f"VIP到期时间: {result['expire_date']}")
                    self.days_label.configure(
                        text=f"剩余 {days_left} 天",
                        foreground='green' if days_left > 7 else 'red'
                    )
                    self.progress_label.configure(text="VIP状态: 有效")
                    
                else:  # VIP 已过期
                    self.progress_bar.configure(style="red.Horizontal.TProgressbar")
                    self.progress_bar['value'] = 0
                    self.vip_label.set("VIP已过期")
                    self.days_label.configure(text="已过期", foreground='red')
                    self.progress_label.configure(text="VIP状态: 已过期")
                    
            else:
                # VIP 检查失败
                self.progress_bar.configure(style="red.Horizontal.TProgressbar")
                self.progress_bar['value'] = 0
                self.vip_label.set("VIP状态检查失败")
                self.days_label.configure(text="检查失败", foreground='red')
                self.progress_label.configure(text="VIP状态: 未知")
                logging.error(f"VIP状态更新失败: {result['message']}")
                
        except Exception as e:
            logging.error(f"更新VIP状态显示失败: {str(e)}")
        finally:
            # 每分钟更新一次
            self.window.after(60000, self.update_vip_status)

    def start_active_timer(self):
        """启动活跃状态更新定时器"""
        try:
            now = datetime.now()
            # 如果距离上次更新超过1分钟才更新
            if not hasattr(self, '_last_active') or (now - self._last_active).total_seconds() >= 60:
                self.db.update_active_time(self.user_id)
                self._last_active = now
                
            # 每30秒检查一次
            self.window.after(30000, self.start_active_timer)
        except Exception as e:
            logging.error(f"更新活跃状态失败: {str(e)}")
            # 如果更新失败，尝试重新连接数据库
            try:
                self.db.connect()
            except:
                pass

    def check_login_status(self):
        """检查登录状态"""
        try:
            # 获取当前设备ID
            current_device = self.db.get_device_id()
            
            # 检查设备状态
            status, message = self.db.check_device_status(self.user_id, current_device)
            
            if not status:
                # 停止所有正在进行的捕获
                if hasattr(self, 'capture_thread') and self.capture_thread.is_alive():
                    self.stop_capture()
                    
                # 保存当前设置
                self.save_settings()
                
                # 如果检测到在其他设备登录，显示提示并退出
                messagebox.showwarning(
                    "设备登录提醒",
                    "您的账号已在其他设备登录，本设备将自动退出。"
                )
                self.window.after(1000, self.logout)  # 1秒后退出
                return
                
        except Exception as e:
            logging.error(f"检查登录状态失败: {str(e)}")
            # 如果检查失败，尝试重新连接数据库
            try:
                self.db.connect()
            except:
                pass
            
        # 每30秒检查一次
        self.window.after(30000, self.check_login_status)

class DatabaseManager:
    def __init__(self):
        self.conn = None
        self.connect()
        # 初始化时更新表结构
        self.update_table_structure()
        
    def update_table_structure(self):
        """更新数据库表结构"""
        try:
            if not self.conn or not self.conn.open:
                self.connect()
                
            cursor = self.conn.cursor()
            
            # 检查 salt 列是否存在
            cursor.execute("""
                SELECT COUNT(*) 
                FROM information_schema.COLUMNS 
                WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME = 'users' 
                AND COLUMN_NAME = 'salt'
            """)
            
            if cursor.fetchone()[0] == 0:
                # 如果 salt 列不存在，添加它
                cursor.execute("ALTER TABLE users ADD COLUMN salt VARCHAR(64) AFTER password")
                
                # 为现有用户生成 salt 并更新密码
                cursor.execute("SELECT id, password FROM users")
                users = cursor.fetchall()
                
                for user_id, old_password in users:
                    # 生成新的 salt
                    salt = os.urandom(16).hex()
                    # 使用新的加密方式重新加密密码
                    new_password = hashlib.sha256(
                        (old_password + salt).encode()
                    ).hexdigest()
                    
                    # 更新用户记录
                    cursor.execute(
                        "UPDATE users SET password=%s, salt=%s WHERE id=%s",
                        (new_password, salt, user_id)
                    )
                
                self.conn.commit()
                logging.info("数据库表结构更新完成")
                
        except Exception as e:
            logging.error(f"更新表结构失败: {str(e)}")
            self.conn.rollback()
        finally:
            cursor.close()
    
    def hash_password(self, password, salt):
        """使用 salt 加密密码"""
        return hashlib.sha256(
            (password + salt).encode()
        ).hexdigest()
    
    def get_device_id(self):
        """获取设备唯一标识"""
        try:
            # 优先使用存储的设备ID
            device_id_file = os.path.join(os.path.expanduser('~'), '.stream_capture', 'device_id')
            if os.path.exists(device_id_file):
                with open(device_id_file, 'r') as f:
                    device_id = f.read().strip()
                    if device_id:  # 确保读取到的ID不为空
                        logging.info(f"使用已保存的设备ID: {device_id}")
                        return device_id
            
            # 如果没有保存的ID或ID为空，生成新的
            device_id = hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()
            logging.info(f"生成新的设备ID: {device_id}")
            
            # 保存设备ID
            try:
                os.makedirs(os.path.dirname(device_id_file), exist_ok=True)
                with open(device_id_file, 'w') as f:
                    f.write(device_id)
                logging.info("设备ID保存成功")
            except Exception as e:
                logging.error(f"保存设备ID失败: {str(e)}")
            
            return device_id
        except Exception as e:
            logging.error(f"获取设备ID失败: {str(e)}")
            # 如果出现错误，生成一个临时ID
            temp_id = hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()
            logging.info(f"使用临时设备ID: {temp_id}")
            return temp_id
            
    def connect(self):
        try:
            self.conn = pymysql.connect(**DBConfig().DB_CONFIG)
        except Exception as e:
            raise Exception(f"数据库连接失败: {str(e)}")

    def login(self, username, password):
        """用户登录"""
        try:
            if not self.conn or not self.conn.open:
                self.connect()
                
            cursor = self.conn.cursor()
            
            # 先获取用户信息
            cursor.execute(
                'SELECT id, password, salt, device_id, last_active, vip_expire_date FROM users WHERE username=%s',
                (username,)
            )
            result = cursor.fetchone()
            
            if not result:
                return {'success': False, 'message': '用户名或密码错误'}
                
            user_id, hashed_pwd, salt, device_id, last_active, vip_expire = result
            
            # 验证密码
            is_valid = False
            if salt:  # 新格式
                is_valid = (self.hash_password(password, salt) == hashed_pwd)
            else:  # 旧格式
                old_hash = hashlib.sha256(
                    (password + DBConfig().SECRET_KEY).encode()
                ).hexdigest()
                is_valid = (old_hash == hashed_pwd)
            
            if not is_valid:
                return {'success': False, 'message': '用户名或密码错误'}
            
            # 获取当前设备ID
            current_device = self.get_device_id()
            
            # 记录设备ID信息用于调试
            logging.info(f"当前设备ID: {current_device}")
            logging.info(f"数据库中的设备ID: {device_id}")
            
            # 检查是否在其他设备登录
            if device_id:  # 只有当数据库中有设备ID时才检查
                if device_id != current_device:  # 如果设备ID不匹配
                    if last_active:  # 如果有最后活跃时间
                        inactive_time = (datetime.now() - last_active).total_seconds()
                        logging.info(f"设备不活跃时间: {inactive_time}秒")
                        
                        if inactive_time < 1800:  # 30分钟内活跃
                            return {
                                'success': False, 
                                'message': '该账号已在其他设备登录\n如果这是您的设备，请等待30分钟后再试\n或联系客服处理'
                            }
                        else:
                            # 如果超过30分钟未活跃，允许新设备登录
                            logging.info("设备超过30分钟未活跃，允许新设备登录")
            
            try:
                # 更新设备ID和最后活跃时间
                cursor.execute(
                    'UPDATE users SET device_id=%s, last_active=NOW() WHERE id=%s',
                    (current_device, user_id)
                )
                self.conn.commit()
                logging.info(f"更新设备ID成功: {current_device}")
            except Exception as e:
                logging.error(f"更新设备信息失败: {str(e)}")
                # 即使更新失败也允许登录
                pass
            
            return {
                'success': True,
                'user_id': user_id,
                'vip_expire': vip_expire.strftime('%Y-%m-%d') if vip_expire else None
            }
            
        except Exception as e:
            logging.error(f"登录失败: {str(e)}")
            return {'success': False, 'message': f"登录失败，请稍后重试\n错误信息: {str(e)}"}
        finally:
            cursor.close()

    def update_active_time(self, user_id):
        """更新用户活跃时间"""
        try:
            if not self.conn or not self.conn.open:
                self.connect()
                
            cursor = self.conn.cursor()
            cursor.execute(
                'UPDATE users SET last_active=NOW() WHERE id=%s',
                (user_id,)
            )
            self.conn.commit()
            logging.debug(f"更新活跃时间成功: user_id={user_id}")
        except Exception as e:
            logging.error(f"更新活跃时间失败: {str(e)}")
            # 尝试重新连接
            try:
                self.connect()
            except:
                pass
        finally:
            cursor.close()
            
    def logout(self, user_id):
        """退出登录，清除设备ID"""
        try:
            if not self.conn or not self.conn.open:
                self.connect()
                
            cursor = self.conn.cursor()
            
            # 立即清除设备ID和最后活跃时间
            cursor.execute(
                'UPDATE users SET device_id=NULL, last_active=NULL WHERE id=%s',
                (user_id,)
            )
            self.conn.commit()
            logging.info(f"用户 {user_id} 退出登录，已清除设备ID")
            return True
            
        except Exception as e:
            logging.error(f"清除设备ID失败: {str(e)}")
            return False
        finally:
            cursor.close()

    def register(self, username, password, email):
        """注册新用户"""
        try:
            if not self.conn or not self.conn.open:
                self.connect()
                
            cursor = self.conn.cursor()
            
            # 检查用户名是否已存在
            cursor.execute('SELECT id FROM users WHERE username=%s', (username,))
            if cursor.fetchone():
                return False, "该用户名已被使用"
            
            # 检查邮箱是否已注册
            cursor.execute('SELECT id FROM users WHERE email=%s', (email,))
            if cursor.fetchone():
                return False, "该邮箱已被注册，每个QQ邮箱只能注册一个账号"
            
            # 生成 salt
            salt = os.urandom(16).hex()
            # 加密密码
            hashed_password = self.hash_password(password, salt)
            
            # 设置1天体验期
            vip_expire = (datetime.now() + timedelta(days=1)).strftime('%Y-%m-%d')
            
            # 插入新用户
            cursor.execute(
                'INSERT INTO users (username, password, salt, email, vip_expire_date) VALUES (%s, %s, %s, %s, %s)',
                (username, hashed_password, salt, email, vip_expire)
            )
            self.conn.commit()
            return True, "注册成功，赠送1天VIP体验期！"
            
        except Exception as e:
            self.conn.rollback()
            logging.error(f"注册失败: {str(e)}")
            return False, str(e)
        finally:
            cursor.close()

    def check_vip(self, user_id):
        """检查用户VIP状态"""
        try:
            if not self.conn or not self.conn.open:
                self.connect()
                
            cursor = self.conn.cursor()
            cursor.execute(
                'SELECT vip_expire_date FROM users WHERE id=%s',
                (user_id,)
            )
            result = cursor.fetchone()
            
            if result and result[0]:
                expire_date = result[0]
                now = datetime.now().date()
                
                # 调试日志
                logging.info(f"VIP检查 - 用户ID: {user_id}")
                logging.info(f"当前日期: {now}")
                logging.info(f"过期日期: {expire_date}")
                
                # 修改比较逻辑：如果过期日期等于当前日期，说明今天还有效
                is_valid = expire_date >= now
                
                if is_valid:
                    # 计算剩余天数
                    days_left = (expire_date - now).days
                    logging.info(f"VIP状态: 有效，剩余 {days_left} 天")
                    return {
                        'success': True,
                        'is_valid': True,
                        'expire_date': expire_date.strftime('%Y-%m-%d'),
                        'days_left': days_left
                    }
                else:
                    logging.info("VIP状态: 已过期")
                    return {
                        'success': True,
                        'is_valid': False,
                        'expire_date': expire_date.strftime('%Y-%m-%d'),
                        'days_left': 0
                    }
            
            logging.info(f"用户 {user_id} 未开通VIP")
            return {
                'success': False,
                'message': '未开通VIP或用户不存在',
                'is_valid': False,
                'days_left': 0
            }
            
        except Exception as e:
            logging.error(f"检查VIP状态失败: {str(e)}")
            return {
                'success': False,
                'message': str(e),
                'is_valid': False,
                'days_left': 0
            }
        finally:
            cursor.close()

    def check_login_status(self, user_id):
        """检查用户登录状态"""
        try:
            if not self.conn or not self.conn.open:
                self.connect()
                
            cursor = self.conn.cursor()
            
            # 获取当前设备ID
            current_device = self.get_device_id()
            
            # 查询用户当前登录的设备和VIP状态
            cursor.execute(
                'SELECT device_id, last_active, vip_expire_date FROM users WHERE id=%s',
                (user_id,)
            )
            result = cursor.fetchone()
            
            if result:
                device_id, last_active, vip_expire = result
                
                # 检查VIP是否过期
                if vip_expire and vip_expire < datetime.now().date():
                    return {
                        'is_valid': False,
                        'message': 'VIP已过期，请续费后继续使用'
                    }
                
                # 检查设备登录状态
                if device_id and device_id != current_device:
                    if last_active and (datetime.now() - last_active).total_seconds() < 300:  # 5分钟
                        return {
                            'is_valid': False,
                            'message': '账号已在其他设备登录'
                        }
                    else:
                        # 如果超过5分钟未活跃，更新设备ID
                        cursor.execute(
                            'UPDATE users SET device_id=%s, last_active=NOW() WHERE id=%s',
                            (current_device, user_id)
                        )
                        self.conn.commit()
            
            return {
                'is_valid': True,
                'message': 'OK'
            }
            
        except Exception as e:
            logging.error(f"检查登录状态失败: {str(e)}")
            return {
                'is_valid': True,  # 出错时默认允许继续使用
                'message': str(e)
            }
        finally:
            cursor.close()

    def __del__(self):
        if self.conn and self.conn.open:
            self.conn.close()

    def check_device_status(self, user_id, device_id):
        """检查设备状态"""
        try:
            if not self.conn or not self.conn.open:
                self.connect()
                
            cursor = self.conn.cursor()
            cursor.execute(
                'SELECT device_id, last_active FROM users WHERE id=%s',
                (user_id,)
            )
            result = cursor.fetchone()
            
            if result:
                current_device, last_active = result
                
                # 如果设备ID不匹配且在5分钟内活跃
                if current_device and current_device != device_id:
                    if last_active and (datetime.now() - last_active).total_seconds() < 300:  # 5分钟
                        logging.info(f"检测到其他设备登录: current={current_device}, this={device_id}")
                        return False, "该账号已在其他设备登录"
                    else:
                        # 如果超过5分钟未活跃，更新设备ID
                        logging.info("设备超过5分钟未活跃，更新设备ID")
                        cursor.execute(
                            'UPDATE users SET device_id=%s, last_active=NOW() WHERE id=%s',
                            (device_id, user_id)
                        )
                        self.conn.commit()
                        
            return True, "OK"
            
        except Exception as e:
            logging.error(f"检查设备状态失败: {str(e)}")
            return True, "检查失败，允许继续使用"
        finally:
            cursor.close()

class EmailVerification:
    def __init__(self, db=None):
        # QQ邮箱配置
        self.sender = '3409266604@qq.com'
        self.password = 'kogacwcucjsqcjcd'
        self.smtp_server = 'smtp.qq.com'
        self.smtp_port = 465
        
        # 验证码有效期（分钟）
        self.code_expire_minutes = 5
        
        # 存储验证码和发送时间
        self.code_cache = {}
        
        # 数据库实例
        self.db = db

    def send_code(self, receiver):
        """发送验证码到QQ邮箱"""
        try:
            # 检查邮箱格式
            if not receiver.endswith('@qq.com'):
                return {
                    'success': False,
                    'message': '请使用QQ邮箱注册'
                }
            
            # 检查邮箱是否已注册
            if self.db:
                try:
                    cursor = self.db.conn.cursor()
                    cursor.execute('SELECT id FROM users WHERE email=%s', (receiver,))
                    if cursor.fetchone():
                        return {
                            'success': False,
                            'message': '该邮箱已被注册，每个QQ邮箱只能注册一个账号'
                        }
                except Exception as e:
                    logging.error(f"检查邮箱失败: {str(e)}")
                finally:
                    cursor.close()
            
            # 生成6位验证码
            code = ''.join(str(random.randint(0, 9)) for _ in range(6))
            
            # 邮件内容
            text = f"""
            您的验证码是：{code}
            
            验证码有效期为{self.code_expire_minutes}分钟，请及时使用。
            如非本人操作，请忽略此邮件。
            
            本邮件由系统自动发送，请勿回复。
            """
            
            # 创建邮件对象
            message = MIMEText(text, "plain", "utf-8")
            message["Subject"] = "注册验证码 - 抖音直播推流码捕获工具"
            message["From"] = "=?utf-8?B?5oqW6Z+z55u05pKt5o6o5rWB56CB5o6l5Y+j5bel5YW3?= <3409266604@qq.com>"
            message["To"] = receiver
            
            # 先保存验证码
            self.code_cache[receiver] = {
                'code': code,
                'time': datetime.now()
            }
            
            # 发送邮件
            try:
                with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
                    server.login(self.sender, self.password)
                    server.sendmail(self.sender, [receiver], message.as_string())
                
                # 发送成功
                return {
                    'success': True,
                    'message': '验证码已发送到您的QQ邮箱'
                }
            except smtplib.SMTPException as e:
                logging.error(f"SMTP错误: {str(e)}")
                # 即使SMTP返回错误，由于验证码已保存，仍然返回成功
                return {
                    'success': True,
                    'message': '验证码已发送到您的QQ邮箱'
                }
            
        except Exception as e:
            logging.error(f"发送验证码失败: {str(e)}")
            # 如果验证码已保存，仍然返回成功
            if receiver in self.code_cache:
                return {
                    'success': True,
                    'message': '验证码已发送到您的QQ邮箱'
                }
            return {
                'success': False,
                'message': '系统错误，请稍后重试'
            }

    def verify_code(self, email, code):
        """验证验证码"""
        try:
            if email not in self.code_cache:
                return False, "请先获取验证码"
                
            cached = self.code_cache[email]
            now = datetime.now()
            
            # 检查是否过期
            if now - cached['time'] > timedelta(minutes=self.code_expire_minutes):
                del self.code_cache[email]
                return False, "验证码已过期，请重新获取"
                
            # 验证码匹配检查
            if code != cached['code']:
                return False, "验证码错误"
                
            # 验证成功后删除缓存
            del self.code_cache[email]
            return True, "验证成功"
        except Exception as e:
            logging.error(f"验证码验证失败: {str(e)}")
            return False, "验证失败，请重试"

if __name__ == "__main__":
    login = LoginWindow()
    login.run() 