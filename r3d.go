// Package and imports
package main

import (
    "bufio"
    "bytes"
    "crypto/tls"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "strings"
    "sync"
    "sync/atomic"
    "time"
)

// Color codes
var (
    red   = "\033[31m"
    cyan  = "\033[36m"
    reset = "\033[0m"
)

// Global variables for payloads
var (
    dirs = []string{
        "/", "/backup/", "/db/", "/database/", "/dump/", "/sql/", "/data/", "/temp/", "/tmp/", "/dumps/", "/web/", "/api/",
        // ... additional directories if needed ...
    }
    filenames = []string{
        "backup", "database", "web", "dump", "db", "data", "sql", "mysqldump", "backup_", "database_", "db_backup", "dump_", "dumpfile", "export", "latest_backup", "site_backup", "website_backup", "wordpress_backup", "joomla_backup", "magento_backup", "wp_backup", "sql_backup", "mysql_backup", "user_data", "customer_data", "production_db", "prod_db", "test_db", "staging_db", "dev_db", "admin_db", "old_db", "new_db", "data_backup", "all_data", "full_backup", "complete_backup", "v1", "backupfile", "dbexport", "dbdumpfile", "{{Hostname}}", "{{Hostname}}_db", "{{Hostname}}_backup", "{{Hostname}}_dump", "{{Hostname}}_{{date_time('%Y%m%d')}}", "backup{{date_time('%Y%m%d')}}", "db{{date_time('%Y%m%d')}}", "database{{date_time('%Y%m%d')}}", "backup{{date_time('%Y-%m-%d')}}", "db{{date_time('%Y-%m-%d')}}", "database{{date_time('%Y-%m-%d')}}", "backup_{{date_time('%Y-%m-%d')}}", "db_{{date_time('%Y-%m-%d')}}",
        // ... additional filenames if appropriate...
    }
    extensions = []string{
        "sql", "sql.gz", "sql.zip", "sql.bz2", "sql.xz", "db", "bak", "zip", "gz", "tar", "tar.gz", "tgz", "rar", "7z", "bak.gz", "bak.zip", "tar.bz2", "bz2", "xz", "dump", "backup", "sql.bak", "sql.tar", "db.gz", "db.zip", "db.bak", "db.tar", "sqlite", "sqlite3", "tmp", "temp", "old", "orig", "copy", "save", "swp", "bk", "old.bak",
        // ... additional extensions if needed...
    }
)

// FileSignature struct to hold file signatures
type FileSignature struct {
    Extension string
    Magic     []byte
    Offset    int
}

// List of file signatures to check against
var fileSignatures = []FileSignature{
    // SQL files
    {Extension: "sql", Magic: []byte("-- MySQL dump"), Offset: -1},
    {Extension: "sql", Magic: []byte("-- PostgreSQL database dump"), Offset: -1},
    {Extension: "sql", Magic: []byte("SQL Server database backup"), Offset: -1},
    {Extension: "sql", Magic: []byte("/*"), Offset: -1},
    {Extension: "sql", Magic: []byte("BEGIN TRANSACTION;"), Offset: -1},
    {Extension: "sql", Magic: []byte("CREATE TABLE"), Offset: -1},
    {Extension: "sql", Magic: []byte("INSERT INTO"), Offset: -1},
    {Extension: "sql", Magic: []byte("DROP TABLE"), Offset: -1},
    // GZIP files
    {Extension: "gz", Magic: []byte{0x1f, 0x8b}, Offset: 0},
    // ZIP files
    {Extension: "zip", Magic: []byte{0x50, 0x4b, 0x03, 0x04}, Offset: 0},
    // BZIP2 files
    {Extension: "bz2", Magic: []byte{0x42, 0x5a, 0x68}, Offset: 0},
    // XZ files
    {Extension: "xz", Magic: []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a}, Offset: 0},
    // 7z files
    {Extension: "7z", Magic: []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}, Offset: 0},
    // Tar files
    {Extension: "tar", Magic: []byte{0x75, 0x73, 0x74, 0x61, 0x72}, Offset: 257},
    // RAR files
    {Extension: "rar", Magic: []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00}, Offset: 0}, // RAR versions 1.5 - 4.0
    {Extension: "rar", Magic: []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00}, Offset: 0}, // RAR 5.0+
    // SQLite database files
    {Extension: "db", Magic: []byte("SQLite format 3"), Offset: 0},
    {Extension: "sqlite", Magic: []byte("SQLite format 3"), Offset: 0},
    {Extension: "sqlite3", Magic: []byte("SQLite format 3"), Offset: 0},
    // Vim swap files
    {Extension: "swp", Magic: []byte{0x42, 0x30}, Offset: 0}, // Starts with "b0"
    // Additional signatures can be added here
}

// Mapping of extensions to their actual types
var extensionMap = map[string]string{
    "sql":        "sql",
    "sql.gz":     "gz",
    "sql.zip":    "zip",
    "sql.bz2":    "bz2",
    "sql.xz":     "xz",
    "sql.tar":    "tar",
    "sql.7z":     "7z",
    "sql.tar.gz": "gz",
    "sql.bak":    "bak", // No specific signature
    "db":         "db",
    "db.gz":      "gz",
    "db.zip":     "zip",
    "db.bz2":     "bz2",
    "db.xz":      "xz",
    "db.tar":     "tar",
    "db.7z":      "7z",
    "db.rar":     "rar",
    "db.bak":     "bak", // No specific signature
    "bak":        "bak", // No specific signature
    "bak.gz":     "gz",
    "bak.zip":    "zip",
    "bak.bz2":    "bz2",
    "bak.xz":     "xz",
    "bak.tar":    "tar",
    "bak.7z":     "7z",
    "bak.rar":    "rar",
    "tar.gz":     "gz",
    "tgz":        "gz",
    "tar.bz2":    "bz2",
    "rar":        "rar",
    "sqlite":     "db",
    "sqlite3":    "db",
    "swp":        "swp",
    // ... additional mappings ...
}

// Error indicators to detect error pages
var errorIndicators = []string{
    "404 Not Found",
    "Error",
    "Page Not Found",
    "The page you requested could not be found",
    "Forbidden",
    "Access Denied",
    "Unauthorized",
    "Error 404",
    "Not Found",
    "Cannot be found",
    "Oops!",
    "Bad Request",
    "400 Bad Request",
    "500 Internal Server Error",
    "Service Unavailable",
    // ... additional phrases ...
}

// Result struct for output
type Result struct {
    URL           string `json:"url"`
    ContentType   string `json:"content_type"`
    ContentLength int64  `json:"content_length"`
    StatusCode    int    `json:"status_code"`
}

// Main function
func main() {
    // Parse command-line flags
    helpFlag := flag.Bool("h", false, "Display help")
    debugFlag := flag.Bool("d", false, "Enable debug mode")
    thresholdFlag := flag.Int("t", 1, "Minimum file size in KB to consider (default: 1KB)")
    maxGoroutinesFlag := flag.Int("c", 20, "Maximum number of concurrent requests (default: 20)")
    jsonOutputFlag := flag.Bool("json", false, "Enable JSON output")
    progressFlag := flag.Bool("p", false, "Display progress")
    dirFlag := flag.String("dir", "", "Specific directory or directories to crawl (comma-separated)")
    fileFlag := flag.String("file", "", "Specific file extension(s) to look for (comma-separated)")
    flag.Parse()

    // Display help if requested
    if *helpFlag {
        displayHelp()
        return
    }

    // Handle specific directories
    if *dirFlag != "" {
        dirs = strings.Split(*dirFlag, ",")
        for i := range dirs {
            dirs[i] = strings.TrimSpace(dirs[i])
        }
    }

    // Handle specific file extensions
    if *fileFlag != "" {
        extensions = strings.Split(*fileFlag, ",")
        for i := range extensions {
            extensions[i] = strings.TrimSpace(extensions[i])
        }
    }

    // Display banner
    displayBanner()

    // Read targets from stdin
    targets := readTargets()

    // Use WaitGroup for concurrency
    var wg sync.WaitGroup

    // Create a channel to limit the number of concurrent goroutines
    maxGoroutines := *maxGoroutinesFlag
    guard := make(chan struct{}, maxGoroutines)

    // Prepare for progress tracking
    totalTasks := int64(len(targets) * len(dirs) * len(filenames) * len(extensions))
    var completedTasks int64 = 0
    startTime := time.Now()

    // Channel to collect results
    resultsChan := make(chan Result, 1000)

    // Start a goroutine to display progress
    if *progressFlag {
        go func() {
            ticker := time.NewTicker(5 * time.Second)
            defer ticker.Stop()
            for range ticker.C {
                progress := float64(atomic.LoadInt64(&completedTasks)) / float64(totalTasks) * 100
                elapsedTime := time.Since(startTime)
                averageTimePerTask := elapsedTime / time.Duration(atomic.LoadInt64(&completedTasks)+1)
                estimatedTotalTime := averageTimePerTask * time.Duration(totalTasks)
                remainingTime := estimatedTotalTime - elapsedTime
                fmt.Printf("Progress: %.2f%% | Elapsed Time: %s | Estimated Remaining Time: %s\n", progress, formatDuration(elapsedTime), formatDuration(remainingTime))
            }
        }()
    }

    // Start a goroutine to handle results
    go func() {
        for result := range resultsChan {
            if *jsonOutputFlag {
                jsonData, err := json.Marshal(result)
                if err == nil {
                    fmt.Println(string(jsonData))
                }
            } else {
                fmt.Printf(red+"Potential file found: %s (Size: %d bytes, Content-Type: %s)\n"+reset, result.URL, result.ContentLength, result.ContentType)
            }
        }
    }()

    // Loop through targets and payloads
    for _, target := range targets {
        for _, dir := range dirs {
            for _, filename := range filenames {
                for _, extension := range extensions {
                    guard <- struct{}{} // Acquire a token
                    wg.Add(1)
                    go func(t, d, f, e string) {
                        defer wg.Done()
                        url := constructURL(t, d, f, e)
                        if *debugFlag {
                            fmt.Println("Probing URL:", url)
                        }
                        if probeURL(url, e, *debugFlag, *thresholdFlag, resultsChan) {
                            // Potential file found, result is already sent to resultsChan
                        }
                        atomic.AddInt64(&completedTasks, 1)
                        <-guard // Release the token
                    }(target, dir, filename, extension)
                }
            }
        }
    }

    // Wait for all goroutines to finish
    wg.Wait()
    close(resultsChan) // Close the results channel
}

// Function to display the help message
func displayHelp() {
    fmt.Println("Usage: cat targets.txt | R3D [-d] [-t threshold] [-c concurrency] [-json] [-p] [-dir directories] [-file extensions]")
    fmt.Println("Options:")
    fmt.Println("  -h, --help          Display this help message")
    fmt.Println("  -d, --debug         Enable debug mode")
    fmt.Println("  -t, --threshold     Minimum file size in KB to consider (default: 1KB)")
    fmt.Println("  -c, --concurrency   Maximum number of concurrent requests (default: 20)")
    fmt.Println("  -json               Enable JSON output")
    fmt.Println("  -p, --progress      Display progress and estimated scan duration")
    fmt.Println("  -dir                Specific directory or directories to crawl (comma-separated)")
    fmt.Println("  -file               Specific file extension(s) to look for (comma-separated)")
}

// Function to display the banner
func displayBanner() {
    fmt.Println(cyan + " ____  ____  ____  " + reset)
    fmt.Println(cyan + "|  _ \\|___ \\|  _ \\ " + reset)
    fmt.Println(cyan + "| |_) | __) | | | |" + reset)
    fmt.Println(cyan + "|  _ <|__ <| |_| |" + reset)
    fmt.Println(cyan + "|_| \\_\\___/|____/ " + reset)
    fmt.Println(cyan + "R3D - Exposed Files Buster by r3dcl1ff" + reset)
    fmt.Println()
}

// Function to read targets from standard input
func readTargets() []string {
    var targets []string
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        target := strings.TrimSpace(scanner.Text())
        if target != "" {
            // Ensure target has a scheme
            if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
                target = "http://" + target
            }
            targets = append(targets, target)
        }
    }
    return targets
}

// Function to construct the URL
func constructURL(baseURL, dir, filename, extension string) string {
    // Ensure baseURL does not end with '/'
    baseURL = strings.TrimSuffix(baseURL, "/")

    // Handle root directory
    if dir == "/" {
        dir = ""
    } else {
        // Ensure dir starts with '/'
        if !strings.HasPrefix(dir, "/") {
            dir = "/" + dir
        }
        // Remove trailing '/' from dir
        dir = strings.TrimSuffix(dir, "/")
    }

    // Parse the hostname
    parsedURL, err := url.Parse(baseURL)
    hostname := ""
    if err == nil {
        hostname = parsedURL.Hostname()
    }

    // Replace placeholders in filename
    filename = strings.ReplaceAll(filename, "{{Hostname}}", hostname)

    // Replace date placeholders
    now := time.Now()
    filename = strings.ReplaceAll(filename, "{{date_time('%Y%m%d')}}", now.Format("20060102"))
    filename = strings.ReplaceAll(filename, "{{date_time('%Y-%m-%d')}}", now.Format("2006-01-02"))

    // Construct the URL
    return fmt.Sprintf("%s%s/%s.%s", baseURL, dir, filename, extension)
}

// Function to probe a single URL
func probeURL(url string, extension string, debug bool, threshold int, resultsChan chan<- Result) bool {
    mappedExt, ok := extensionMap[extension]
    if !ok {
        mappedExt = extension
    }

    // Increase timeout and allow skipping SSL verification if needed
    client := &http.Client{
        Timeout: 30 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Use with caution
        },
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if len(via) >= 10 {
                return http.ErrUseLastResponse
            }
            return nil
        },
    }

    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        if debug {
            fmt.Println("Request creation error:", err)
        }
        return false
    }

    // Set headers
    req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    req.Header.Set("Accept", "*/*")

    // Retry mechanism
    var resp *http.Response
    for attempts := 0; attempts < 3; attempts++ {
        resp, err = client.Do(req)
        if err == nil {
            break
        }
        time.Sleep(time.Duration(attempts+1) * time.Second) // Exponential backoff
    }
    if err != nil {
        if debug {
            fmt.Println("HTTP request error:", err)
        }
        return false
    }
    defer resp.Body.Close()

    // Check for status code 200 or 206
    if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent {
        // Check Content-Length
        contentLength := resp.ContentLength

        if debug {
            fmt.Printf("Probing URL: %s\n", url)
            fmt.Printf("Status Code: %d\n", resp.StatusCode)
            fmt.Printf("Content-Length: %d\n", contentLength)
            fmt.Printf("Content-Type: %s\n", resp.Header.Get("Content-Type"))
        }

        // Read first few kilobytes to check content
        body, err := io.ReadAll(io.LimitReader(resp.Body, 16384)) // Read up to 16KB
        if err != nil {
            if debug {
                fmt.Println("Error reading response body:", err)
            }
            return false
        }

        // Check for error pages
        if strings.Contains(resp.Header.Get("Content-Type"), "text/html") && isErrorPage(body) {
            if debug {
                fmt.Println("Detected error page for", url)
            }
            return false
        }

        if debug && len(body) > 0 {
            fmt.Printf("First few bytes of response: %s\n", string(body[:min(len(body), 256)]))
        }

        // Check if body matches known signatures
        if matchesSignature(body, mappedExt) {
            // Check if contentLength is less than threshold
            if contentLength > 0 && contentLength < int64(threshold)*1024 {
                if debug {
                    fmt.Printf("Content-Length %d is less than %dKB but signature matches\n", contentLength/1024, threshold)
                }
                // Still consider it since signature matches
                resultsChan <- Result{
                    URL:           url,
                    ContentType:   resp.Header.Get("Content-Type"),
                    ContentLength: contentLength,
                    StatusCode:    resp.StatusCode,
                }
                return true
            } else {
                resultsChan <- Result{
                    URL:           url,
                    ContentType:   resp.Header.Get("Content-Type"),
                    ContentLength: contentLength,
                    StatusCode:    resp.StatusCode,
                }
                return true
            }
        } else {
            if debug {
                fmt.Println("No matching file signature found for", url)
            }
        }
    } else {
        if debug {
            fmt.Printf("Received HTTP status %d for %s\n", resp.StatusCode, url)
        }
    }
    return false
}

// Function to check if the response body matches known file signatures
func matchesSignature(body []byte, extension string) bool {
    for _, sig := range fileSignatures {
        if sig.Extension == extension {
            if sig.Offset >= 0 {
                if len(body) >= len(sig.Magic)+sig.Offset {
                    if bytes.Equal(body[sig.Offset:sig.Offset+len(sig.Magic)], sig.Magic) {
                        return true
                    }
                }
            } else {
                if bytes.Contains(body, sig.Magic) {
                    return true
                }
            }
        }
    }
    return false
}

// Function to check if the response body is likely an error page
func isErrorPage(body []byte) bool {
    s := strings.ToLower(string(body))
    if strings.Contains(s, "<html") || strings.Contains(s, "<head") || strings.Contains(s, "<title>") || strings.Contains(s, "<body") {
        return true
    }
    for _, indicator := range errorIndicators {
        if strings.Contains(s, strings.ToLower(indicator)) {
            return true
        }
    }
    return false
}

// Helper function to get minimum of two integers
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

// Function to format duration of scan
func formatDuration(d time.Duration) string {
    d = d.Round(time.Second)
    h := d / time.Hour
    d -= h * time.Hour
    m := d / time.Minute
    d -= m * time.Minute
    s := d / time.Second

    if h > 0 {
        return fmt.Sprintf("%02dh%02dm%02ds", h, m, s)
    } else if m > 0 {
        return fmt.Sprintf("%02dm%02ds", m, s)
    } else {
        return fmt.Sprintf("%02ds", s)
    }
}
