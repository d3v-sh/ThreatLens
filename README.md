# ThreatLens

```
  _____ _                    _   _                    
 |_   _| |__  _ __ ___  __ _| |_| |    ___ _ __  ___ 
   | | | '_ \| '__/ _ \/ _' | __| |   / _ \ '_ \/ __|
   | | | | | | | |  __/ (_| | |_| |__|  __/ | | \__ \
   |_| |_| |_|_|  \___|\__,_|\__|_____\___|_| |_|___/
                                                      
                    Made by d1_d3m0n
```

A powerful, configuration-driven host security scanner for Windows that detects suspicious processes, malicious PowerShell execution, and potential compromise indicators using osquery.

## Features

✨ **Configuration-Driven Detection**
- External rule definitions in JSON
- Easy to add/modify detection rules
- No recompilation needed

🎯 **Smart Detection**
- Suspicious process locations (AppData, Temp)
- Encoded PowerShell commands
- PowerShell download cradles
- Execution policy bypasses
- Hidden PowerShell windows
- Unusual CMD executions
- Credential dumping tools (Mimikatz)
- Network reconnaissance tools

🛡️ **False Positive Reduction**
- Configurable exclusion rules
- Pre-defined whitelist for common legitimate apps
- Customizable severity levels

🎨 **Professional Output**
- Color-coded results (Clean/Suspicious/Compromised)
- MITRE ATT&CK technique mapping
- Detailed evidence collection
- Risk scoring system

## Prerequisites

- **Windows OS** (Windows 10/11 or Windows Server)
- **osquery** - Download from [osquery.io](https://osquery.io/downloads/official)
- **Go 1.16+** (for building from source)

## Installation

### 1. Install osquery

Download and install osquery for Windows:
```powershell
# Download from https://osquery.io/downloads/official
# Run the .msi installer as Administrator
# Default installation path: C:\Program Files\osquery\
```

Verify installation:
```powershell
"C:\Program Files\osquery\osqueryi.exe" --version
```

### 2. Install ThreatLens

**Option A: Download Pre-built Binary** (Coming Soon)
```powershell
# Download the latest release from GitHub
# Extract and run
```

**Option B: Build from Source**
```bash
git clone https://github.com/yourusername/ThreatLens.git
cd ThreatLens
go build -o ThreatLens.exe main.go
```

## Usage

### Basic Scan

Run ThreatLens as Administrator:
```powershell
# Run as Administrator
.\ThreatLens.exe
```

### First Run

On first run, ThreatLens will:
1. Check if osquery is installed
2. Create default `detection_rules.json` and `queries.json` if missing
3. Perform a security scan

### Understanding Results

**Risk Scores:**
- **CLEAN** (0-39): No significant threats detected
- **SUSPICIOUS** (40-69): Potentially malicious activity
- **COMPROMISED** (70+): High-confidence threat detection

**Example Output:**
```
========== Host Security Scanner ==========
✓ Osquery is installed and working
✓ Loaded 2 queries
✓ Loaded 10 detection rules

Available queries:
  - processes (enabled)
  - listening_ports (enabled)

✓ Found 245 processes
✓ Found 12 listening ports

==================================================
HOST SECURITY ASSESSMENT RESULTS
==================================================

Status: SUSPICIOUS
Risk Score: 40
Total Detections: 1

1. [T1059.001] PowerShell Hidden Window
   Severity: 40
   Evidence: Process: powershell.exe | PID: 5678 | Path: C:\Windows\System32\...
==================================================
```

## Configuration

### Detection Rules (`detection_rules.json`)

Rules define what to detect. Each rule has:

```json
{
  "id": "RULE_ID",
  "title": "Rule Title",
  "description": "What this detects",
  "data_source": "processes",
  "conditions": [
    {
      "field": "cmdline",
      "operator": "contains",
      "value": "suspicious_string"
    }
  ],
  "exclusions": [
    {
      "field": "name",
      "operator": "contains",
      "value": "legitimate.exe"
    }
  ],
  "severity": 40,
  "mitre": "T1059.001"
}
```

**Supported Operators:**
- `contains` - Substring match
- `equals` - Exact match
- `not_equals` - Not equal
- `starts_with` - Prefix match
- `ends_with` - Suffix match

### Queries (`queries.json`)

Queries define what data to collect from osquery:

```json
{
  "queries": [
    {
      "name": "processes",
      "sql": "SELECT pid, parent, name, path, cmdline, start_time FROM processes;",
      "description": "List all running processes",
      "enabled": true
    }
  ]
}
```

### Adding Custom Rules

1. Edit `detection_rules.json`
2. Add your rule following the format above
3. Run ThreatLens (no recompilation needed!)

**Example - Detect Suspicious Downloads:**
```json
{
  "id": "CUSTOM_001",
  "title": "Browser Download of Executable",
  "description": "Detect .exe downloads in browser temp",
  "data_source": "processes",
  "conditions": [
    {
      "field": "path",
      "operator": "contains",
      "value": "\\downloads\\"
    },
    {
      "field": "name",
      "operator": "ends_with",
      "value": ".exe"
    }
  ],
  "exclusions": [],
  "severity": 30,
  "mitre": "T1566.001"
}
```

## Reducing False Positives

Add legitimate software to exclusions in `detection_rules.json`:

```json
"exclusions": [
  {
    "field": "name",
    "operator": "contains",
    "value": "yourapp.exe"
  },
  {
    "field": "path",
    "operator": "contains",
    "value": "\\your\\trusted\\path\\"
  }
]
```

## MITRE ATT&CK Coverage

ThreatLens currently detects techniques from:

- **T1059** - Command and Scripting Interpreter
- **T1059.001** - PowerShell
- **T1059.003** - Windows Command Shell
- **T1059.005** - Visual Basic
- **T1003.001** - LSASS Memory (Credential Dumping)
- **T1046** - Network Service Scanning

## Project Structure

```
ThreatLens/
├── main.go                  # Main scanner code
├── detection_rules.json     # Detection rule definitions
├── queries.json             # osquery queries
├── README.md               # This file
├── LICENSE                 # MIT License
└── .gitignore             # Git ignore file
```

## Troubleshooting

### "osquery not found"
- Ensure osquery is installed at `C:\Program Files\osquery\osqueryi.exe`
- Run installer as Administrator

### "Error loading rules"
- Check JSON syntax in `detection_rules.json`
- Ensure file exists in same directory as executable

### No detections found
- Run as Administrator
- Check if queries are enabled in `queries.json`
- Verify osquery is returning data: `osqueryi.exe --json "SELECT * FROM processes LIMIT 5;"`

### False Positives
- Add exclusions to `detection_rules.json`
- Adjust severity levels as needed

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Ideas for Contributions

- Additional detection rules
- Support for other osquery tables (registry, services, etc.)
- Linux/macOS support
- JSON/CSV report output
- Scheduled scanning
- Integration with SIEM systems

## Roadmap

- [ ] Additional data sources (registry, scheduled tasks, services)
- [ ] Report generation (JSON, CSV, HTML)
- [ ] Baseline comparison mode
- [ ] Real-time monitoring
- [ ] Linux and macOS support
- [ ] Web dashboard
- [ ] Alert notifications

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for **authorized security testing and educational purposes only**. Users are responsible for complying with applicable laws and regulations. The author assumes no liability for misuse.

## Acknowledgments

- [osquery](https://osquery.io/) - Endpoint visibility framework
- [MITRE ATT&CK](https://attack.mitre.org/) - Threat intelligence framework

## Author

**d1_d3m0n**

## Support

If you find ThreatLens useful, please ⭐ star the repository!

For issues and feature requests, please use the [GitHub Issues](https://github.com/yourusername/ThreatLens/issues) page.
