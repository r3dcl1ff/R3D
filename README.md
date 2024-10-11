Usage: cat targets.txt | ./r3d [-d] [-t threshold] [-c concurrency] [-json] [-p] [-dir directories] [-file extensions]


Options:

-h, --help          (Display this help message)

-d, --debug         (Enable debug mode)

-t, --threshold     (Minimum file size in KB to consider , default: 1KB)

-c, --concurrency   (Maximum number of concurrent requests ,default: 20)

-json               (Enable JSON output)

-p, --progress      (Display progress and estimated scan duration)

-dir                (Specific directory or directories to crawl ,comma-separated)

-file               (Specific file extension to look for ,comma-separated)
