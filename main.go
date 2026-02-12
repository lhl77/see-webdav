package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	_ "modernc.org/sqlite"
)

const (
	DB_FILE       = "see.db"
	CONFIG_FILE   = "config.json"
	SMMS_UPLOAD   = "https://s.ee/api/v1/file/upload"
	SMMS_DELETE   = "https://s.ee/api/v1/file/delete/"
	MAX_FILE_SIZE = 20 * 1024 * 1024 // 20MB
)

type Config struct {
	SeeToken string `json:"see_token"`
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type FileInfo struct {
	Hash         string    `json:"hash"`
	Path         string    `json:"path"`
	OriginalPath string    `json:"original_path"`
	URL          string    `json:"url"`
	Size         int64     `json:"size"`
	Modified     time.Time `json:"modified"`
	IsDir        bool      `json:"is_dir"`
}

var (
	db     *sql.DB
	config Config
	client *resty.Client
)

// ------------------ Config ------------------
func loadConfig() error {
	if _, err := os.Stat(CONFIG_FILE); os.IsNotExist(err) {
		defaultConf := Config{
			SeeToken: "",
			Port:     "8080",
			Username: "",
			Password: "",
		}
		data, _ := json.MarshalIndent(defaultConf, "", "  ")
		os.WriteFile(CONFIG_FILE, data, 0600)
		fmt.Printf("🔧 %s not found. Created template. Please edit it and restart.\n", CONFIG_FILE)
		os.Exit(1)
	}

	data, err := os.ReadFile(CONFIG_FILE)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	if config.Port == "" {
		config.Port = "8080"
	}

	return nil
}

// ------------------ SQLite DB ------------------
func initDB() error {
	var err error
	db, err = sql.Open("sqlite", DB_FILE+"?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=30000")
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}

	// 创建表（如果不存在）
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS files (
			path TEXT PRIMARY KEY,
			original_path TEXT,
			hash TEXT NOT NULL,
			url TEXT NOT NULL,
			size INTEGER NOT NULL,
			modified TEXT NOT NULL,
			is_dir INTEGER NOT NULL DEFAULT 0
		);
	`)
	if err != nil {
		return fmt.Errorf("create table: %w", err)
	}

	// 检查表结构是否完整
	if err := checkAndFixTableStructure(); err != nil {
		return fmt.Errorf("check table structure: %w", err)
	}

	return nil
}

// 检查并修复表结构
func checkAndFixTableStructure() error {
	// 查询表的列信息
	rows, err := db.Query("PRAGMA table_info(files);")
	if err != nil {
		return fmt.Errorf("query table info: %w", err)
	}
	defer rows.Close()

	// 收集现有列名
	existingColumns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dfltValue interface{}
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return fmt.Errorf("scan table info: %w", err)
		}
		existingColumns[name] = true
	}

	// 定义需要的列及其类型
	requiredColumns := map[string]string{
		"path":          "TEXT PRIMARY KEY",
		"original_path": "TEXT",
		"hash":          "TEXT NOT NULL",
		"url":           "TEXT NOT NULL",
		"size":          "INTEGER NOT NULL",
		"modified":      "TEXT NOT NULL",
		"is_dir":        "INTEGER NOT NULL DEFAULT 0",
	}

	// 检查并添加缺失的列
	for column, columnType := range requiredColumns {
		if !existingColumns[column] {
			fmt.Printf("⚠️  Column '%s' is missing. Adding it to the table...\n", column)
			alterQuery := fmt.Sprintf("ALTER TABLE files ADD COLUMN %s %s;", column, columnType)
			if _, err := db.Exec(alterQuery); err != nil {
				return fmt.Errorf("add column '%s': %w", column, err)
			}
		}
	}

	return nil
}

func saveFile(info *FileInfo) error {
	modifiedStr := info.Modified.Format(time.RFC3339)
	_, err := db.Exec(
		"INSERT OR REPLACE INTO files (path, original_path, hash, url, size, modified, is_dir) VALUES (?, ?, ?, ?, ?, ?, ?)",
		info.Path, info.OriginalPath, info.Hash, info.URL, info.Size, modifiedStr, info.IsDir,
	)
	return err
}

// ------------------ DB Helpers ------------------
func getFile(path string) (*FileInfo, error) {
	row := db.QueryRow("SELECT hash, url, size, modified FROM files WHERE path = ?", path)
	var info FileInfo
	var modifiedStr string
	err := row.Scan(&info.Hash, &info.URL, &info.Size, &modifiedStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	info.Path = path
	info.Modified, _ = time.Parse(time.RFC3339, modifiedStr)
	return &info, nil
}

// 按 original_path 查询
func getFileByOriginalPath(originalPath string) (*FileInfo, error) {
	row := db.QueryRow("SELECT path, original_path, hash, url, size, modified FROM files WHERE original_path = ?", originalPath)
	var info FileInfo
	var modifiedStr string
	err := row.Scan(&info.Path, &info.OriginalPath, &info.Hash, &info.URL, &info.Size, &modifiedStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	info.Modified, _ = time.Parse(time.RFC3339, modifiedStr)
	return &info, nil
}

func deleteFile(path string) error {
	_, err := db.Exec("DELETE FROM files WHERE path = ?", path)
	return err
}

func listAllFiles() ([]FileInfo, error) {
	rows, err := db.Query("SELECT path, original_path, hash, url, size, modified FROM files ORDER BY original_path")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []FileInfo
	for rows.Next() {
		var f FileInfo
		var modifiedStr string
		if err := rows.Scan(&f.Path, &f.OriginalPath, &f.Hash, &f.URL, &f.Size, &modifiedStr); err != nil {
			return nil, err
		}
		f.Modified, _ = time.Parse(time.RFC3339, modifiedStr)
		files = append(files, f)
	}
	return files, nil
}

// ------------------ API ------------------
type SmmsImage struct {
	Filename  string `json:"filename"`
	Size      int    `json:"size"`
	Path      string `json:"path"`
	Hash      string `json:"hash"`
	URL       string `json:"url"`
	CreatedAt int    `json:"created_at"`
}

func uploadToSmms(filename string, content []byte) (*FileInfo, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("smfile", filename)
	part.Write(content)
	writer.Close()

	req := client.R().
		SetHeader("Content-Type", writer.FormDataContentType()).
		SetBody(body.Bytes())

	if config.SeeToken != "" {
		req.SetHeader("Authorization", config.SeeToken)
	}

	resp, err := req.Post(SMMS_UPLOAD)
	if err != nil {
		return nil, err
	}

	var result struct {
		Data    SmmsImage `json:"data"`
		Message string    `json:"message"`
		Code    int       `json:"code"`
	}
	json.Unmarshal(resp.Body(), &result)

	if result.Code != 200 {
		if strings.Contains(result.Message, "Image exists") {
			return nil, fmt.Errorf("file already exists on s.ee (duplicate content)")
		}
		return nil, fmt.Errorf("s.ee: %s", result.Message)
	}

	mtime := time.Now()
	if result.Data.CreatedAt > 0 {
		mtime = time.Unix(int64(result.Data.CreatedAt), 0)
	}

	return &FileInfo{
		Hash:     result.Data.Hash,
		URL:      result.Data.URL,
		Size:     int64(result.Data.Size),
		Modified: mtime,
	}, nil
}

func deleteFromSmms(hash string) error {
	url := SMMS_DELETE + hash
	req := client.R()
	if config.SeeToken != "" {
		req.SetHeader("Authorization", config.SeeToken)
	}
	resp, err := req.Get(url)
	if err != nil {
		return err
	}

	var result struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	json.Unmarshal(resp.Body(), &result)

	if !result.Success {
		return fmt.Errorf("delete failed: %s", result.Message)
	}
	return nil
}

// ------------------ WebDAV XML Types------------------
type Prop struct {
	Resourcetype *struct {
		Collection *struct{} `xml:"D:collection,omitempty"`
	} `xml:"D:resourcetype,omitempty"`
	Getcontentlength *int64 `xml:"D:getcontentlength,omitempty"`
	Creationdate     string `xml:"D:creationdate,omitempty"`
	Getlastmodified  string `xml:"D:getlastmodified,omitempty"`
}

type Propstat struct {
	Prop   Prop   `xml:"D:prop"`
	Status string `xml:"D:status"`
}

type PropfindResponseItem struct {
	Href  string   `xml:"D:href"`
	Props Propstat `xml:"D:propstat"`
}

type PropfindResponse struct {
	XMLName   xml.Name               `xml:"D:multistatus"`
	XmlnsD    string                 `xml:"xmlns:D,attr"`
	Responses []PropfindResponseItem `xml:"D:response"`
}

// ------------------ WebDAV Handler ------------------
func normalizePath(p string) string {
	p = strings.TrimPrefix(p, "/")
	if p == "" || strings.Contains(p, "..") {
		return ""
	}
	return p
}

// escapePathSegments 对路径按段进行 URL 转义，保留段间的 `/` 并正确保留尾部 `/`（如果存在）。
func escapePathSegments(p string) string {
	if p == "" {
		return ""
	}
	trailing := strings.HasSuffix(p, "/")
	p = strings.TrimSuffix(p, "/")
	parts := strings.Split(p, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	res := strings.Join(parts, "/")
	if trailing {
		res += "/"
	}
	return res
}

func webdavHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("DAV", "1, 2")
	w.Header().Set("Allow", "GET, HEAD, PUT, POST, DELETE, PROPFIND, OPTIONS, MKCOL")

	path := normalizePath(r.URL.Path)

	switch r.Method {
	case "PUT":
		handlePUT(w, r, path)
	case "DELETE":
		handleDELETE(w, r, path)
	case "GET", "HEAD":
		handleGET(w, r, path)
	case "PROPFIND":
		handlePROPFIND(w, r, path)
	case "MKCOL":
		handleMKCOL(w, r, path)
	case "OPTIONS":
		handleOPTIONS(w, r, path)
	case "MOVE":
		handleMOVE(w, r, path)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT, POST, DELETE, PROPFIND, OPTIONS, MKCOL")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// 处理创建文件夹的请求
func handleMKCOL(w http.ResponseWriter, r *http.Request, path string) {
	if path == "" {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// 去掉前导 /，并确保目录以 / 结尾用于存储和比较
	p := strings.TrimPrefix(path, "/")
	if !strings.HasSuffix(p, "/") {
		p = p + "/"
	}

	// 检查是否已存在（尝试 original_path 带/不带两种形式）
	existing, err := getFileByOriginalPath(p)
	if err != nil {
		http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if existing == nil {
		existing, err = getFileByOriginalPath(strings.TrimSuffix(p, "/"))
		if err != nil {
			http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if existing == nil {
		existing, err = getFile(p)
		if err != nil {
			http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if existing == nil {
			existing, err = getFile(strings.TrimSuffix(p, "/"))
			if err != nil {
				http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}
	if existing != nil {
		http.Error(w, "Folder already exists", http.StatusConflict)
		return
	}

	// 验证父目录存在（除非父为根目录）
	parent := strings.TrimSuffix(p, "/")
	parent = filepath.Dir(parent)
	if parent != "." && parent != "" {
		parentOK, err := getFileByOriginalPath(parent)
		if err != nil {
			http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if parentOK == nil {
			parentOK, err = getFileByOriginalPath(parent + "/")
			if err != nil {
				http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if parentOK == nil {
			parentOK, err = getFile(parent)
			if err != nil {
				http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if parentOK == nil {
				parentOK, err = getFile(parent + "/")
				if err != nil {
					http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}
		if parentOK == nil {
			http.Error(w, "Parent directory does not exist", http.StatusConflict)
			return
		}
	}

	// 创建文件夹记录（使用带尾斜线的 p）
	now := time.Now()
	err = saveFile(&FileInfo{
		Path:         p,
		OriginalPath: p,
		Hash:         "",
		URL:          "",
		Size:         0,
		Modified:     now,
		IsDir:        true,
	})
	if err != nil {
		http.Error(w, "Failed to create folder: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("[+] Folder created: %s\n", p)
	w.WriteHeader(http.StatusCreated)
}

func handleOPTIONS(w http.ResponseWriter, r *http.Request, path string) {
	w.Header().Set("Allow", "GET, HEAD, PUT, POST, DELETE, PROPFIND, OPTIONS")
	w.Header().Set("DAV", "1, 2")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusNoContent)
}

func handlePUT(w http.ResponseWriter, r *http.Request, name string) {
	if name == "" {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	if r.ContentLength > 0 && r.ContentLength > MAX_FILE_SIZE {
		http.Error(w, "File too large", http.StatusRequestEntityTooLarge)
		return
	}

	content, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("[-] Error reading request body for file %s: %v\n", name, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(content) > MAX_FILE_SIZE {
		http.Error(w, "File too large", http.StatusRequestEntityTooLarge)
		return
	}

	// 确保路径是合法的
	dir := filepath.Dir(name)
	if dir != "." {
		// 检查父目录是否存在（尝试带/不带尾部斜线两种形式以兼容 DB 存储差异）
		parentDir, err := getFileByOriginalPath(dir)
		if err != nil {
			http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if parentDir == nil {
			// 尝试另一个形式（带或不带尾部斜线）
			var alt string
			if strings.HasSuffix(dir, "/") {
				alt = strings.TrimSuffix(dir, "/")
			} else {
				alt = dir + "/"
			}
			parentDir, err = getFileByOriginalPath(alt)
			if err != nil {
				http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if parentDir == nil {
			// 如果父目录不存在，尝试自动创建（mkdir -p 行为）
			if err := ensureDirExists(dir); err != nil {
				fmt.Printf("[-] Failed to auto-create parent directories for %s: %v\n", dir, err)
				http.Error(w, "Parent directory does not exist and could not be created", http.StatusConflict)
				return
			}
		}
	}

	info, err := uploadToSmms(filepath.Base(name), content)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			http.Error(w, "File already exists (duplicate content)", http.StatusConflict)
			return
		}
		fmt.Printf("[-] Upload failed for file %s: %v\n", name, err)
		http.Error(w, "Upload failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	info.OriginalPath = name

	var finalPath string
	if u, err := url.Parse(info.URL); err == nil {
		finalPath = strings.TrimPrefix(u.Path, "/")
	} else {
		// 如果解析失败，回退到原始 name
		finalPath = strings.TrimPrefix(name, "/")
	}

	// 确保不为空
	if finalPath == "" {
		finalPath = filepath.Base(name)
	}

	info.Path = finalPath

	if err := saveFile(info); err != nil {
		fmt.Printf("[-] Failed to save file info for %s to DB: %v\n", name, err)
		http.Error(w, "Save to DB failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("[+] Uploaded and saved: original=%s -> stored as=%s (key: %s)\n", name, info.Path, info.Hash)
	w.WriteHeader(http.StatusCreated)
}

func handleDELETE(w http.ResponseWriter, r *http.Request, inputPath string) {
	if inputPath == "" {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// 查询文件或文件夹信息
	info, err := getFile(inputPath)
	if err != nil {
		http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if info == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if info.IsDir {
		// 如果是文件夹，递归删除文件夹及其内容
		rows, err := db.Query("SELECT path FROM files WHERE path LIKE ?", inputPath+"/%")
		if err != nil {
			http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var childPath string
			if err := rows.Scan(&childPath); err != nil {
				http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
				return
			}
			handleDELETE(w, r, childPath) // 递归删除子文件或子文件夹
		}
	}

	// 删除当前文件或文件夹
	_, err = db.Exec("DELETE FROM files WHERE path = ?", inputPath)
	if err != nil {
		http.Error(w, "DB delete failed", http.StatusInternalServerError)
		return
	}

	// 调用 s.ee 删除（用 hash ）
	if err := deleteFromSmms(info.Hash); err != nil {
		fmt.Printf("[-] Delete warning (s.ee): %v\n", err)
	}

	fmt.Printf("[-] Deleted: %s\n", inputPath)
	w.WriteHeader(http.StatusNoContent)
}

func handleGET(w http.ResponseWriter, r *http.Request, originalPath string) {
	if originalPath == "" {
		// 当请求根路径时，强制认证
		if config.Username != "" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != config.Username || pass != config.Password {
				w.Header().Set("WWW-Authenticate", `Basic realm="s.ee WebDAV"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		handlePROPFIND(w, r, "")
		return
	}

	info, err := getFileByOriginalPath(originalPath)
	if err != nil {
		fmt.Printf("[-] DB error while trying to get file by original path '%s': %v\n", originalPath, err)
		http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if info == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// If this is a directory, return PROPFIND (directory listing) instead of proxying
	displayPath := info.OriginalPath
	if displayPath == "" {
		displayPath = info.Path
	}
	if info.IsDir || strings.HasSuffix(displayPath, "/") {
		// Ensure authentication for directory listing if configured
		if config.Username != "" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != config.Username || pass != config.Password {
				w.Header().Set("WWW-Authenticate", `Basic realm="s.ee WebDAV"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		handlePROPFIND(w, r, displayPath)
		return
	}

	// 反向代理到 s.ee 的 URL
	proxyReq, err := http.NewRequest("GET", info.URL, nil)
	if err != nil {
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		return
	}

	// 复制原始请求的头信息，但移除不支持的头
	for key, values := range r.Header {
		if strings.ToLower(key) == "connection" || strings.ToLower(key) == "upgrade" {
			continue // 跳过不支持的头
		}
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		fmt.Printf("[-] Failed to fetch file from upstream: %v\n", err)
		http.Error(w, "Failed to fetch file from upstream", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	io.Copy(w, resp.Body)
}

func handlePROPFIND(w http.ResponseWriter, r *http.Request, name string) {
	if name == "" {
		files, err := listAllFiles()
		if err != nil {
			fmt.Printf("[-] DB error while listing files: %v\n", err)
			http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		responses := []PropfindResponseItem{
			{
				Href: "/",
				Props: Propstat{
					Prop: Prop{
						Resourcetype: &struct {
							Collection *struct{} `xml:"D:collection,omitempty"`
						}{
							Collection: &struct{}{},
						},
					},
					Status: "HTTP/1.1 200 OK",
				},
			},
		}

		for _, info := range files {
			displayPath := info.OriginalPath
			if displayPath == "" {
				displayPath = info.Path
			}
			if decoded, err := url.PathUnescape(displayPath); err == nil {
				displayPath = decoded
			}
			href := "/" + escapePathSegments(displayPath)

			creation := info.Modified.UTC().Format(time.RFC3339)
			lm := info.Modified.UTC().Format(time.RFC1123)
			lm = strings.ReplaceAll(lm, "UTC", "GMT")

			var prop Prop
			if info.IsDir || strings.HasSuffix(displayPath, "/") {
				prop = Prop{
					Resourcetype: &struct {
						Collection *struct{} `xml:"D:collection,omitempty"`
					}{
						Collection: &struct{}{},
					},
					Creationdate:    creation,
					Getlastmodified: lm,
				}
			} else {
				prop = Prop{
					Getcontentlength: &info.Size,
					Creationdate:     creation,
					Getlastmodified:  lm,
				}
			}

			responses = append(responses, PropfindResponseItem{
				Href: href,
				Props: Propstat{
					Prop:   prop,
					Status: "HTTP/1.1 200 OK",
				},
			})
		}

		w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
		w.Header().Set("DAV", "1, 2")
		w.WriteHeader(http.StatusMultiStatus)

		resp := PropfindResponse{
			XmlnsD:    "DAV:",
			Responses: responses,
		}
		xml.NewEncoder(w).Encode(resp)
		return
	}

	lookupName := name
	info, err := getFileByOriginalPath(lookupName)
	if err != nil {
		fmt.Printf("[-] DB error while checking path '%s': %v\n", lookupName, err)
		http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if info == nil {
		if strings.HasSuffix(lookupName, "/") {
			lookupName = strings.TrimSuffix(lookupName, "/")
		} else {
			lookupName = lookupName + "/"
		}
		info, _ = getFileByOriginalPath(lookupName)
	}

	hasChildren := false
	likePattern := name
	if !strings.HasSuffix(likePattern, "/") {
		likePattern = likePattern + "/%"
	} else {
		likePattern = likePattern + "%"
	}
	row := db.QueryRow("SELECT 1 FROM files WHERE original_path LIKE ? LIMIT 1", likePattern)
	var tmp int
	if err := row.Scan(&tmp); err == nil {
		hasChildren = true
	}

	if info != nil && (info.IsDir || strings.HasSuffix(lookupName, "/") || hasChildren) {
		responses := []PropfindResponseItem{}

		displayPath := lookupName
		if displayPath == "" {
			displayPath = name
		}
		if !strings.HasSuffix(displayPath, "/") {
			displayPath += "/"
		}
		if decoded, err := url.PathUnescape(displayPath); err == nil {
			displayPath = decoded
		}
		folderHref := "/" + escapePathSegments(displayPath)

		creation := time.Now().UTC().Format(time.RFC3339)
		if info != nil {
			creation = info.Modified.UTC().Format(time.RFC3339)
		}
		lm := time.Now().UTC().Format(time.RFC1123)
		lm = strings.ReplaceAll(lm, "UTC", "GMT")
		if info != nil {
			lm = info.Modified.UTC().Format(time.RFC1123)
			lm = strings.ReplaceAll(lm, "UTC", "GMT")
		}

		folderProp := Prop{
			Resourcetype: &struct {
				Collection *struct{} `xml:"D:collection,omitempty"`
			}{
				Collection: &struct{}{},
			},
			Creationdate:    creation,
			Getlastmodified: lm,
		}
		responses = append(responses, PropfindResponseItem{Href: folderHref, Props: Propstat{Prop: folderProp, Status: "HTTP/1.1 200 OK"}})

		rows, err := db.Query("SELECT original_path, size, modified, is_dir FROM files WHERE original_path = ? OR original_path LIKE ? ORDER BY original_path", strings.TrimSuffix(name, "/"), likePattern)
		if err != nil {
			fmt.Printf("[-] DB error while listing children of '%s': %v\n", name, err)
			http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var op string
			var size int64
			var modifiedStr string
			var isDirInt int
			if err := rows.Scan(&op, &size, &modifiedStr, &isDirInt); err != nil {
				fmt.Printf("[-] DB scan error: %v\n", err)
				continue
			}
			// 跳过与目录自身同名的记录，避免重复（归一化前后斜线后比较）
			folderNoTrail := strings.TrimSuffix(strings.TrimPrefix(name, "/"), "/")
			opNorm := strings.TrimSuffix(strings.TrimPrefix(op, "/"), "/")
			if opNorm == folderNoTrail {
				continue
			}
			mod, _ := time.Parse(time.RFC3339, modifiedStr)
			childDisplay := op
			if decoded, err := url.PathUnescape(childDisplay); err == nil {
				childDisplay = decoded
			}
			childHref := "/" + escapePathSegments(childDisplay)
			// format times
			creation := mod.UTC().Format(time.RFC3339)
			lm := mod.UTC().Format(time.RFC1123)
			lm = strings.ReplaceAll(lm, "UTC", "GMT")
			var prop Prop
			if isDirInt != 0 || strings.HasSuffix(op, "/") {
				prop = Prop{
					Resourcetype: &struct {
						Collection *struct{} `xml:"D:collection,omitempty"`
					}{
						Collection: &struct{}{},
					},
					Creationdate:    creation,
					Getlastmodified: lm,
				}
			} else {
				prop = Prop{
					Getcontentlength: &size,
					Creationdate:     creation,
					Getlastmodified:  lm,
				}
			}
			responses = append(responses, PropfindResponseItem{Href: childHref, Props: Propstat{Prop: prop, Status: "HTTP/1.1 200 OK"}})
		}

		w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
		w.Header().Set("DAV", "1, 2")
		w.WriteHeader(http.StatusMultiStatus)

		resp := PropfindResponse{XmlnsD: "DAV:", Responses: responses}
		xml.NewEncoder(w).Encode(resp)
		return
	}

	info, err = getFileByOriginalPath(name)
	if err != nil {
		fmt.Printf("[-] DB error while trying to get file by original path '%s': %v\n", name, err)
		http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if info == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	displayPath := info.OriginalPath
	if displayPath == "" {
		displayPath = info.Path
	}
	href := "/" + escapePathSegments(displayPath)
	creation := info.Modified.UTC().Format(time.RFC3339)
	lm := info.Modified.UTC().Format(time.RFC1123)
	lm = strings.ReplaceAll(lm, "UTC", "GMT")
	prop := Prop{
		Getcontentlength: &info.Size, // Size in bytes
		Creationdate:     creation,
		Getlastmodified:  lm,
	}
	response := PropfindResponseItem{
		Href: href,
		Props: Propstat{
			Prop:   prop,
			Status: "HTTP/1.1 200 OK",
		},
	}

	w.Header().Set("Content-Type", `application/xml; charset="utf-8"`)
	w.Header().Set("DAV", "1, 2")
	w.WriteHeader(http.StatusMultiStatus)

	resp := PropfindResponse{
		XmlnsD:    "DAV:",
		Responses: []PropfindResponseItem{response},
	}
	xml.NewEncoder(w).Encode(resp)
}

func hasChildren(original string) (bool, error) {
	rows, err := db.Query("SELECT 1 FROM files WHERE original_path LIKE ? LIMIT 1", original+"/%")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	if rows.Next() {
		return true, nil
	}
	return false, nil
}

// 修改文件名
func handleMOVE(w http.ResponseWriter, r *http.Request, oldPath string) {
	if oldPath == "" {
		http.Error(w, "Invalid source path", http.StatusBadRequest)
		return
	}

	// 获取目标路径
	destination := r.Header.Get("Destination")
	if destination == "" {
		http.Error(w, "Missing Destination header", http.StatusBadRequest)
		return
	}

	// 如果 Destination 是完整 URL，提取其 Path 部分；否则直接使用 header 内容
	var destPath string
	if u, err := url.Parse(destination); err == nil && u.Scheme != "" && u.Host != "" {
		// 使用 URL 的 Path 部分（去掉前导 /）
		destPath = strings.TrimPrefix(u.Path, "/")
	} else {
		// 可能是绝对/相对路径，直接去掉前导 /
		destPath = strings.TrimPrefix(destination, "/")
	}

	// 规范化并校验目标路径
	destination = normalizePath(destPath)
	if destination == "" {
		http.Error(w, "Missing or invalid Destination path", http.StatusBadRequest)
		return
	}

	// 检查源文件是否存在
	sourceFile, err := getFileByOriginalPath(oldPath)
	if err != nil {
		http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if sourceFile == nil {
		http.Error(w, "Source file not found", http.StatusNotFound)
		return
	}

	// 使用事务通过 UPDATE 修改 original_path（保留 path 不变）
	if err := moveFile(oldPath, destination); err != nil {
		http.Error(w, "Move failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Printf("[+] Renamed file: %s -> %s\n", oldPath, destination)
	w.WriteHeader(http.StatusCreated)
}

// moveFile 使用 SQL UPDATE 修改 original_path 字段，保持 path (主键) 不变。
func moveFile(oldOrig, newOrig string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// 确认源存在并获取 is_dir
	var isDir int
	var dbPath string
	row := tx.QueryRow("SELECT path, is_dir FROM files WHERE original_path = ?", oldOrig)
	if err := row.Scan(&dbPath, &isDir); err != nil {
		if err == sql.ErrNoRows {
			tx.Rollback()
			return fmt.Errorf("source not found")
		}
		tx.Rollback()
		return err
	}

	// 检查目标是否存在
	row = tx.QueryRow("SELECT 1 FROM files WHERE original_path = ?", newOrig)
	var tmp int
	if err := row.Scan(&tmp); err == nil {
		tx.Rollback()
		return fmt.Errorf("destination already exists")
	} else if err != sql.ErrNoRows {
		tx.Rollback()
		return err
	}

	if isDir != 0 {
		// 更新目录自身及其子项
		likePattern := oldOrig + "/%"
		rows, err := tx.Query("SELECT original_path FROM files WHERE original_path = ? OR original_path LIKE ?", oldOrig, likePattern)
		if err != nil {
			tx.Rollback()
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var cur string
			if err := rows.Scan(&cur); err != nil {
				tx.Rollback()
				return err
			}
			newPath := strings.Replace(cur, oldOrig, newOrig, 1)
			if _, err := tx.Exec("UPDATE files SET original_path = ? WHERE original_path = ?", newPath, cur); err != nil {
				tx.Rollback()
				return err
			}
		}
		if err := rows.Err(); err != nil {
			tx.Rollback()
			return err
		}
	} else {
		if _, err := tx.Exec("UPDATE files SET original_path = ? WHERE original_path = ?", newOrig, oldOrig); err != nil {
			tx.Rollback()
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	return nil
}

func main() {
	if err := loadConfig(); err != nil {
		fmt.Printf("❌ Config error: %v\n", err)
		os.Exit(1)
	}

	client = resty.New().SetTimeout(60 * time.Second)

	if err := initDB(); err != nil {
		fmt.Printf("❌ DB init failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🚀 s.ee WebDAV server running on :%s\n", config.Port)
	fmt.Printf("📁 DB: %s\n", DB_FILE)
	fmt.Printf("⚙️  Config: %s\n", CONFIG_FILE)
	if config.SeeToken != "" {
		fmt.Println("🔑 Using s.ee token from config")
	} else {
		fmt.Println("🔓 Running in anonymous mode (no token)")
	}
	fmt.Println("😽 Github: lhl77/see-webdav")

	authHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			if config.Username != "" {
				user, pass, ok := r.BasicAuth()
				if !ok || user != config.Username || pass != config.Password {
					w.Header().Set("WWW-Authenticate", `Basic realm="s.ee WebDAV"`)
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
		}
		webdavHandler(w, r)
	}

	http.HandleFunc("/api/get-url", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		originalPath := normalizePath(r.URL.Query().Get("path"))
		if originalPath == "" {
			http.Error(w, "Missing or invalid path", http.StatusBadRequest)
			return
		}

		info, err := getFileByOriginalPath(originalPath)
		if err != nil {
			http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if info == nil {
			info, err = getFile(originalPath)
			if err != nil {
				http.Error(w, "DB error: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		if info == nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]string{
			"url": info.Path,
		})
	})

	http.HandleFunc("/", authHandler)
	if err := http.ListenAndServe(":"+config.Port, nil); err != nil {
		fmt.Printf("💥 Server failed: %v\n", err)
	}

}

func ensureDirExists(dir string) error {
	if dir == "" || dir == "." {
		return nil
	}
	p := strings.TrimPrefix(dir, "/")
	if !strings.HasSuffix(p, "/") {
		p = p + "/"
	}
	parts := strings.Split(strings.TrimSuffix(p, "/"), "/")
	acc := ""
	for i := range parts {
		if acc == "" {
			acc = parts[i]
		} else {
			acc = acc + "/" + parts[i]
		}
		dirPath := acc + "/"
		exists, err := getFileByOriginalPath(dirPath)
		if err != nil {
			return err
		}
		if exists == nil {
			exists, err = getFile(strings.TrimSuffix(dirPath, "/"))
			if err != nil {
				return err
			}
			if exists == nil {
				now := time.Now()
				if err := saveFile(&FileInfo{
					Path:         dirPath,
					OriginalPath: dirPath,
					Hash:         "",
					URL:          "",
					Size:         0,
					Modified:     now,
					IsDir:        true,
				}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
