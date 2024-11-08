# simpleWebDAV

本项目实现了基本登录认证和SSL支持的WebDAV服务器.允许用户通过WebDAV协议提供文件服务,并具有可定制的设置,如允许的文件扩展名、最大文件大小和SSL配置.

## 功能

- **基本认证**: 使用用户名和密码登录WebDAV服务.
- **SSL支持**: 启用SSL以加密数据传输.如果启用了SSL且未找到对应证书文件,程序将生成自签名证书.
- **文件扩展名过滤**: 限制文件上传到特定的扩展名.
- **最大文件大小**: 设置可以上传的文件的最大大小.
- **自动目录清理**: 自动删除macOS的"._*系列文件"数据和零字节文件.

## 使用方法

### 命令行参数

- `-address`: 监听地址 (默认: `localhost`).
- `-port`: 监听端口 (默认: `8080`).
- `-username`: 登录用户名.如果未提供,将生成一个随机的用户名和密码并存储在`auth.json`中.
- `-password`: 登录密码.
- `-path`: 文件存储的目录 (默认: `./files`).如果目录不存在,将自动创建.
- `-ext`: 允许的文件扩展名列表,逗号分隔 (例如: `.pdf,.xlsx`).
- `-maxsize`: 上传文件的最大允许大小 (例如: `10M`, `2G`).
- `-ssl`: 启用SSL.如果未找到`cert.pem`和`key.pem`文件,将生成自签名证书.
- `-help` 或 `-h`: 显示帮助信息.

### 示例

```bash
go run main.go -address=localhost -port=8080 -username=admin -password=secret -path=./files -ext=.pdf,.xlsx -maxsize=10M -ssl
```

## 安装

1. 确保你的系统上已安装Go.
2. 克隆此仓库:

   ```bash
   git clone https://github.com/yourusername/webdav-server.git
   cd webdav-server
   ```

3. 运行程序:

   ```bash
   go run main.go
   ```

4. 如果需要编译成二进制运行程序,参考Makefile

## 访问服务器

启动服务器后,可以通过在浏览器或WebDAV客户端中输入服务器的IP地址或域名加上端口号直接访问.不需要特定的后缀地址.

### Windows连接问题

Windows默认只支持可信的SSL证书进行HTTPS WebDAV连接,不支持自签名SSL证书与HTTP连接.要通过HTTP和基本认证连接到WebDAV服务器,请按照以下步骤操作：

1. **修改Windows注册表**:
   - 创建一个包含以下内容的bat文件,并以管理员身份运行：

     ```batch
     @echo off 
     reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient\Parameters /v BasicAuthLevel /t REG_DWORD /d 2 /f
     reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient\Parameters /v FileSizeLimitInBytes /t REG_DWORD /d 0xffffffff /f
     %1 mshta vbscript:CreateObject("Shell.Application").ShellExecute("cmd.exe","/c %~s0 ::","","runas",1)(window.close)&&exit
     cd /d "%~dp0"
     net stop WebClient
     net start WebClient
     exit
     ```

2. **映射网络驱动器**:
   - 在“我的电脑”中,选择“映射网络驱动器”.
   - 选择“使用其他凭据连接”.
   - 输入WebDAV服务器URL（例如：`http://WEBDAV-SERVER/`）.
   - 在提示时提供用户名和密码.

也可以在CMD中使用以下命令添加：

```batch
net use * http://WEBDAV-SERVER/ /user:USERNAME /persistent:YES PASSWORD
```

### 文件上传问题

某些文件可能无法上传,因为`main.go`文件中的`isForbiddenFile()`函数对文件扩展名进行了过滤.该函数过滤了一些与远程执行、恶意软件或病毒相关的文件扩展名.如果需要修改禁止的扩展名列表,可以相应地编辑`isForbiddenFile()`函数.

#### 默认限制的文件后缀

```
// html后缀
"html", "htm", "shtml", "xhtml", "xht", "xhtm",
// PHP相关后缀
"php", "php5", "pht", "phtml", "shtml", "pwml", "phtm",
// JSP相关后缀
"jspx", "jsp", "jspf", "jspa", "jsw", "jsv", "jtml",
// ASP相关后缀
"asa", "asax", "cer", "cdx", "aspx", "ascx", "ashx", "asmx", "asp", "asp80", "asp81", "asp82", "asp83", "asp84", "asp85", "asp86", "asp87", "asp88", "asp89", "asp90",
// 其他危险后缀
"vbs", "asis", "sh", "bash", "csh", "ksh", "zsh", "reg", "cgi", "exe", "msi", "wsf", "hta", "cpl", "drv", "sys", "dll", "com", "bat", "pl", "cfc", "cfm", "ini",
```

## 安全考虑

- **自签名证书**: 当启用SSL且未找到证书文件时,程序会生成自签名证书.这适用于测试,但不推荐用于生产环境.
- **基本认证**: 基本认证用于简单性.对于生产环境,建议使用更安全的认证方法.

## 贡献

欢迎贡献！请随时提交拉取请求或打开问题.

## 许可证

本项目采用MIT许可证.

