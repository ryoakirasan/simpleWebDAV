# simpleWebDAV

This project implements a basic login authentication and SSL-enabled WebDAV server. It allows users to serve files via the WebDAV protocol with customizable settings such as allowed file extensions, maximum file size, and SSL configuration.

## Features

- **Basic Authentication**: Log in to the WebDAV service using a username and password.
- **SSL Support**: Enable SSL to encrypt data transmission. If SSL is enabled and the corresponding certificate files are not found, the program will generate a self-signed certificate.
- **File Extension Filtering**: Restrict file uploads to specific extensions.
- **Maximum File Size**: Set the maximum size of files that can be uploaded.
- **Automatic Directory Cleanup**: Automatically delete macOS "._*" series files and zero-byte files.

## Usage

### Command Line Arguments

- `-address`: Listening address (default: `localhost`).
- `-port`: Listening port (default: `8080`).
- `-username`: Login username. If not provided, a random username and password will be generated and stored in `auth.json`.
- `-password`: Login password.
- `-path`: Directory for file storage (default: `./files`). The directory will be created automatically if it does not exist.
- `-ext`: List of allowed file extensions, comma-separated (e.g., `.pdf,.xlsx`).
- `-maxsize`: Maximum allowed size for uploaded files (e.g., `10M`, `2G`).
- `-ssl`: Enable SSL. If the `cert.pem` and `key.pem` files are not found, a self-signed certificate will be generated.
- `-help` or `-h`: Display help information.

### Example

```bash
go run main.go -address=localhost -port=8080 -username=admin -password=secret -path=./files -ext=.pdf,.xlsx -maxsize=10M -ssl
```

## Installation

1. Ensure Go is installed on your system.
2. Clone this repository:

   ```bash
   git clone https://github.com/yourusername/webdav-server.git
   cd webdav-server
   ```

3. Run the program:

   ```bash
   go run main.go
   ```

4. If you need to compile into a binary executable, refer to the Makefile.

## Accessing the Server

After starting the server, you can access it directly by entering the server's IP address or domain name plus the port number in a browser or WebDAV client. No specific suffix address is required.

### Windows Connection Issues

Windows only supports HTTPS WebDAV connections with trusted SSL certificates and does not support self-signed SSL certificates or HTTP connections. To connect to the WebDAV server via HTTP and basic authentication, follow these steps:

1. **Modify Windows Registry**:
   - Create a batch file containing the following content and run it as an administrator:

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

2. **Map Network Drive**:
   - In "My Computer", select "Map Network Drive".
   - Choose "Connect using different credentials".
   - Enter the WebDAV server URL (e.g., `http://WEBDAV-SERVER/`).
   - Provide the username and password when prompted.

Alternatively, you can add it using the following command in CMD:

```batch
net use * http://WEBDAV-SERVER/ /user:USERNAME /persistent:YES PASSWORD
```

### File Upload Issues

Some files may not be uploaded because the `isForbiddenFile()` function in the `main.go` file filters file extensions. This function filters out extensions related to remote execution, malware, or viruses. If you need to modify the list of forbidden extensions, you can edit the `isForbiddenFile()` function accordingly.

## Security Considerations

- **Self-Signed Certificates**: When SSL is enabled and certificate files are not found, the program generates a self-signed certificate. This is suitable for testing but not recommended for production environments.
- **Basic Authentication**: Basic authentication is used for simplicity. For production environments, it is recommended to use more secure authentication methods.

## Contributing

Contributions are welcome! Feel free to submit pull requests or open issues.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
