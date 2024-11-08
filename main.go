package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"golang.org/x/net/webdav"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	var address, port, username, password, path, maxSize, extensions string
	var ssl, help bool
	flag.StringVar(&address, "address", "localhost", "监听地址")
	flag.StringVar(&port, "port", "8080", "端口监听")
	flag.StringVar(&username, "username", "", "认证用户名")
	flag.StringVar(&password, "password", "", "认证密码")
	flag.StringVar(&path, "path", "./files", "WebDAV文件存储路径,留空将会自动生成files目录作为路径")
	flag.StringVar(&extensions, "ext", "", "允许的文件扩展名,逗号分隔,例如：\".pdf,.xlsx\"")
	flag.StringVar(&maxSize, "maxsize", "", "允许上传的最大文件大小,例如：10M,2G")
	flag.BoolVar(&ssl, "ssl", false, "启用SSL,如果目录下存在同名的cert.pem和key.pem会自动引用,如果没有会生成自签证书")
	flag.BoolVar(&help, "help", false, "显示帮助信息")
	flag.BoolVar(&help, "h", false, "显示帮助信息")

	flag.Parse()
	// 检查是否传入了 --help 或 -h 参数
	if help {
		flag.Usage()
		return
	}
	// 如果密码为空,则生成一个随机密码写入到特定文件中
	// username、password如果没有赋值，在本地生成一个auth.json文件，里面是一个对象，有username和password
	if username == "" || password == "" {
		authFilePath := filepath.Join("auth.json")
		if _, err := os.Stat(authFilePath); os.IsNotExist(err) {
			fmt.Println("用户名或密码为空,生成随机密码并写入到auth.json文件中")
			// 生成随机密码
			password = generateRandomPassword(10)
			authData := map[string]string{
				"username": "user",
				"password": password,
			}
			authJSON, err := json.MarshalIndent(authData, "", "  ")
			if err != nil {
				log.Fatalf("无法生成JSON: %v", err)
			}
			err = os.WriteFile(authFilePath, authJSON, 0644)
			if err != nil {
				log.Fatalf("无法写入auth.json文件: %v", err)
			}
		} else {
			// 读取auth.json文件
			authJSON, err := os.ReadFile(authFilePath)
			if err != nil {
				log.Fatalf("无法读取auth.json文件: %v", err)
			}
			var authData map[string]string
			err = json.Unmarshal(authJSON, &authData)
			if err != nil {
				log.Fatalf("无法解析auth.json文件: %v", err)
			}
			fmt.Println("auth.json存在,读取auth.json中登录用户名与密码")
			username = authData["username"]
			password = authData["password"]
		}
	}
	// 组合地址和端口
	listenAddress := fmt.Sprintf("%s:%s", address, port)

	// 验证并处理路径
	absPath, err := validateAndNormalizePath(path)
	if err != nil {
		fmt.Printf("路径验证异常: %s\n", err)
		return
	}

	// 创建WebDAV处理器
	handler := &webdav.Handler{
		FileSystem: webdav.Dir(absPath),
		LockSystem: webdav.NewMemLS(),
	}
	// 解析上传文件大小的限制
	var maxUploadSize int64
	if maxSize != "" {
		maxUploadSize, err = parseMaxSize(maxSize)
		if err != nil {
			fmt.Printf("文件大小体积转换异常: %s\n", err)
			return
		}
	}

	// 解析允许的文件后缀
	allowedExtensions := parseExtensions(extensions)

	// 创建HTTP服务器,并添加基本认证
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 检查用户名和密码
		user, pass, ok := r.BasicAuth()
		if !ok || user != username || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// 检查文件后缀
		if r.Method == "PUT" {
			filename := filepath.Base(r.URL.Path)
			ext := strings.ToLower(filepath.Ext(filename))
			if (len(allowedExtensions) > 0 && !allowedExtensions[ext]) || isForbiddenFile(filename) {
				http.Error(w, "未经允许的文件后缀", http.StatusForbidden)
				return
			}
		}
		if r.Method == "MOVE" || r.Method == "COPY" {
			destination := r.Header.Get("Destination")
			if destination != "" {
				ext := strings.ToLower(filepath.Ext(destination))
				if (len(allowedExtensions) > 0 && !allowedExtensions[ext]) || isForbiddenFile(destination) {
					http.Error(w, "未经允许的文件后缀", http.StatusForbidden)
					return
				}
			}
		}
		// 限制上传文件大小
		if r.Method == "PUT" && maxUploadSize > 0 {
			// 从请求头中获取预期的实体长度
			// MACOS自带的文件管理系统连接WebDAV服务器时,会自动添加该请求头
			entitySizeStr := r.Header.Get("X-Expected-Entity-Length")
			if entitySizeStr == "" {
				// 如果没有该请求头,则使用Content-Length
				entitySizeStr = r.Header.Get("Content-Length")
			}
			entitySize, _ := strconv.ParseInt(entitySizeStr, 10, 64)
			if entitySize > maxUploadSize {
				http.Error(w, "文件超出体积限制", http.StatusRequestEntityTooLarge)
				return
			}
			// 防止对应请求头都没有体积参数
			bodySize, newBody, _ := getFileSize(r.Body)
			if bodySize > maxUploadSize {
				http.Error(w, "文件超出体积限制", http.StatusRequestEntityTooLarge)
				newBody = io.NopCloser(nil)
				return
			}
			r.Body = newBody
		}
		// 处理WebDAV请求
		if r.Body != nil {
			handler.ServeHTTP(w, r)
			watchDirectoryRemoveFile(absPath)
		}
	})

	// 启动HTTP服务器
	if ssl {
		// 检查是否存在同名证书文件
		certFile := "cert.pem"
		keyFile := "key.pem"
		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			// 生成自签名证书
			cert, key, err := generateSelfSignedCert()
			if err != nil {
				fmt.Printf("生成自签名证书时出错: %s\n", err)
				return
			}

			// 保存证书和密钥到文件
			if err := os.WriteFile(certFile, cert, 0600); err != nil {
				fmt.Printf("写入证书文件时出错: %s\n", err)
				return
			}
			if err := os.WriteFile(keyFile, key, 0600); err != nil {
				fmt.Printf("写入密钥文件时出错: %s\n", err)
				return
			}
		}

		// 配置TLS
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12, // 最低支持TLS 1.2
			MaxVersion: tls.VersionTLS13, // 最高支持TLS 1.3
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
		}

		// 启动HTTPS服务器
		server := &http.Server{
			Addr:      listenAddress,
			TLSConfig: tlsConfig,
		}

		fmt.Printf("启动 WebDAV 服务(SSL) %s 文件存储路径: %s\n", listenAddress, absPath)
		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
			fmt.Printf("启动 WebDAV 服务(SSL)异常: %s\n", err)
		}
	} else {
		// 启动HTTP服务器
		fmt.Printf("启动 WebDAV 服务 %s 文件存储路径: %s\n", listenAddress, absPath)
		if err := http.ListenAndServe(listenAddress, nil); err != nil {
			fmt.Printf("启动 WebDAV 服务异常: %s\n", err)
		}
	}
}

// 随机密码生成
func generateRandomPassword(length int) string {
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var password strings.Builder
	for i := 0; i < length; i++ {
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		password.WriteByte(charset[randomIndex.Int64()])
	}
	return password.String()
}

// 获取body大小
func getFileSize(body io.ReadCloser) (int64, io.ReadCloser, error) {
	// 使用 io.TeeReader 将请求体复制到一个缓冲区中,并计算其大小
	var buf bytes.Buffer
	teeReader := io.TeeReader(body, &buf)
	size, err := io.Copy(&buf, teeReader)
	if err != nil {
		fmt.Println("读取文件体积异常: ", err)
		return 0, nil, err
	}
	return size, io.NopCloser(&buf), nil
}

// 监听目录并删除符合条件的文件,删除macos的脏数据和字节为0的数据
func watchDirectoryRemoveFile(dir string) {
	// 遍历目录并删除符合条件的文件
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			// 删除macos的脏数据文件
			if strings.HasPrefix(info.Name(), "._") || info.Size() == 0 {
				err := os.Remove(path)
				if err != nil {
					return err
				}
			}
			// 删除包含危险后缀的文件
			if isForbiddenFile(info.Name()) {
				err := os.Remove(path)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("工作目录异常 %s: %v\n", dir, err)
	}
}

// parseMaxSize 解析上传文件大小的限制
func parseMaxSize(maxSize string) (int64, error) {
	var size int64
	var unit string

	// 使用正则表达式解析大小和单位
	_, err := fmt.Sscanf(maxSize, "%d%s", &size, &unit)
	if err != nil {
		return 0, fmt.Errorf("错误的最大文件体积: %s", maxSize)
	}

	// 根据单位转换为字节数
	switch strings.ToLower(unit) {
	case "g", "gb":
		size *= 1024 * 1024 * 1024
	case "m", "mb":
		size *= 1024 * 1024
	case "k", "kb":
		size *= 1024
	default:
		return 0, fmt.Errorf("错误的符号: %s", unit)
	}

	return size, nil
}

// 检查文件名是否包含不允许的后缀
func isForbiddenFile(filename string) bool {
	// 定义不允许的后缀列表
	var forbiddenSuffixes = []string{
		// html后缀
		"html", "htm", "shtml", "xhtml", "xht", "xhtm", "xht",
		// PHP相关后缀
		"php", "php5", "pht", "phtml", "shtml", "pwml", "phtm",
		// JSP相关后缀
		"jspx", "jsp", "jspf", "jspa", "jsw", "jsv", "jtml",
		// ASP相关后缀
		"asa", "asax", "cer", "cdx", "aspx", "ascx", "ashx", "asmx", "asp", "asp80", "asp81", "asp82", "asp83", "asp84", "asp85", "asp86", "asp87", "asp88", "asp89", "asp90",
		// 其他危险后缀
		"vbs", "asis", "sh", "bash", "csh", "ksh", "zsh", "reg", "cgi", "exe", "msi", "wsf", "hta", "cpl", "drv", "sys", "dll", "com", "bat", "pl", "cfc", "cfm", "ini",
	}
	// 从文件名末尾开始检查
	parts := strings.Split(filename, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		suffix := parts[i]
		for _, forbidden := range forbiddenSuffixes {
			if suffix == forbidden {
				return true
			}
		}
	}
	return false
}

// 解析允许的文件后缀
func parseExtensions(extensions string) map[string]bool {
	extMap := make(map[string]bool)
	if extensions == "" {
		return extMap
	}
	extList := strings.Split(extensions, ",")
	for _, ext := range extList {
		ext = strings.ToLower(strings.TrimSpace(ext))
		extMap[ext] = true
	}
	return extMap
}

// 生成自签名证书
func generateSelfSignedCert() (certPEM, keyPEM []byte, err error) {
	// 生成RSA密钥对
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("RSA key生成异常: %w", err)
	}

	// 创建证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "localhost",
			Organization:       []string{"WebDAV"},
			OrganizationalUnit: []string{"Development"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 10),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 生成自签名证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("证书生成异常: %w", err)
	}

	// 编码证书和密钥为PEM格式
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return certPEM, keyPEM, nil
}

// 验证并规范化路径
func validateAndNormalizePath(path string) (string, error) {
	// 获取当前工作目录
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("获取当前文件目录时出错: %w", err)
	}

	// 将相对路径转换为绝对路径
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("将目录路径转换为绝对路径时出错: %w", err)
	}
	// 确保路径是当前工作目录的子目录
	if absPath == wd || !strings.HasPrefix(absPath, wd) {
		return "", fmt.Errorf("目录路径必须是当前文件目录的子目录")
	}
	// 检查文件夹是否存在
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		// 文件夹不存在,创建它
		err := os.Mkdir(absPath, 0755)
		if err != nil {
			return "", err
		}
	}
	return absPath, nil
}
