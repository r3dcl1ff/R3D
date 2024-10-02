Usage: cat targets.txt | R3D [-d] [-t threshold] [-c concurrency] [-json] [-p]


Options:


  -h, --help          Display this help message
  -d, --debug         Enable debug mode
  -t, --threshold     Minimum file size in KB to consider (default: 1KB)
  -c, --concurrency   Maximum number of concurrent requests (default: 20)
  -json               Enable JSON output
  -p, --progress      Display progress and estimated scan duration
