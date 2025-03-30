# 抖音直播推流码捕获工具

一个用于捕获抖音直播推流地址的工具，基于 Python 开发。

## 功能特点

- 自动捕获抖音直播推流地址
- 多网卡支持
- 用户账号系统
- VIP会员管理
- 单设备登录限制
- 安全的密码加密存储
- QQ邮箱验证码注册

## 技术栈

- Python 3.12
- tkinter (GUI)
- MySQL (数据库)
- cryptography (加密)
- pyinstaller (打包)
- Inno Setup (安装包制作)

## 系统要求

- Windows 7/8/10/11
- 需要管理员权限运行
- 需要安装 WinPcap 或 Npcap

## 开发环境搭建

1. 安装 Python 3.12
2. 安装依赖：
```bash
pip install -r requirements.txt
```
3. 安装 MySQL 数据库
4. 导入数据库结构：
```sql
source database.sql
```
5. 配置数据库连接：
   - 复制 `src/config.template.py` 为 `src/config.py`
   - 修改 `config.py` 中的数据库配置信息

## 项目结构

```
├── src/                    # 源代码
│   ├── stream_capture.py   # 主程序
│   ├── database.py        # 数据库管理
│   └── utils.py           # 工具函数
├── build.py               # 构建脚本
├── setup.iss              # 安装包配置
├── requirements.txt       # 项目依赖
└── README.md             # 项目文档
```

## 更新日志

### v2.0
- 新增单设备登录限制
- 优化设备切换逻辑
- 设备锁定时间从30分钟改为5分钟
- 新增新用户注册送1天VIP体验
- 改进密码加密存储方式
- 优化用户界面

### v1.0
- 基础功能实现
- 用户系统
- VIP管理
- 推流码捕获

## 开发注意事项

1. 设备ID管理
   - 退出登录时立即清除设备ID
   - 设备锁定时间为5分钟
   - 超过5分钟未活跃允许其他设备登录

2. VIP管理
   - 新用户注册送1天体验
   - VIP过期当天仍可使用
   - 定时检查VIP状态

3. 安全性
   - 密码加盐存储
   - 验证码5分钟有效
   - 登录失败限制

4. 安全提示
   - 不要提交 config.py 到版本控制系统
   - 保护好数据库凭据
   - 定期更换密钥和密码
   - 使用环境变量存储敏感信息

## 构建发布

1. 运行构建脚本：
```bash
python build.py
```

2. 生成安装包：
```bash
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" setup.iss
```

## 联系方式

- 作者：记得晚安科技
- 微信：Hatebetray_