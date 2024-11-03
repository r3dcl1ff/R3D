# R3D Exposed Files Buster

## Overview
R3D is designed to identify potentially exposed files on web servers by probing various URLs. It scans for backup, database, and other critical file types across a range of directories and file extensions.

## Features
- **Customizable Probing**: Specify directories and file extensions for targeted scanning.
- **Concurrency**: Configurable number of concurrent requests to optimize scanning speed.
- **File Signature Matching**: Checks file contents for known signatures to confirm file types.
- **Error Page Detection**: Identifies and skips common error pages to reduce false positives.
- **JSON Output**: Optional JSON output for easy integration with other tools.
- **Progress Monitoring**: Displays progress and estimated time for completion.

## Installation
1. Ensure Go is installed on your system.
2. Clone this repository:
   ```
   git clone https://github.com/r3dcl1ff/R3D.git
   ```
5. Build the script:
   ```
   go build r3d.go
   cp r3d /usr/local/bin
   r3d -h
   ```

## Usage
Pipe a list of target URLs to the script:
```
cat targets.txt | r3d [-options]
```

### Options
- `-h, --help`: Display help message.
- `-d, --debug`: Enable debug mode.
- `-t, --threshold`: Set minimum file size in KB to consider (default: 1KB).
- `-c, --concurrency`: Maximum number of concurrent requests (default: 20).
- `-json`: Enable JSON output.
- `-p, --progress`: Show progress and estimated scan duration.
- `-dir`: Specify directory or directories to scan (comma-separated).
- `-file`: Specify file extensions to search for (comma-separated).

## Example
Scan a list of targets with a specified directory and file extension:
```
cat targets.txt | r3d -dir "/backup,/db" -file "sql,zip" -c 50 -json
```

## Contributing
Feel free to submit issues and pull requests for improvements or new features.

## License
This project is licensed under the MIT License.

---
*Disclaimer: Use responsibly and only on systems you have permission to test.*


