# Screwed File Monitor

A lightweight file integrity monitoring tool that detects unauthorized changes to files by calculating and comparing SHA-256 hashes.

Never happened to lose files due to file system failure or corruption? And when you need them, you found they were corrupted for so long that all your backups don't have a good copy.

Screwed File Monitor detects file alterations or corruption and warns you, so you can get a fresh copy from your backups.

## Features

- Monitor files and directories for changes
- Detect file modifications via SHA-256 hash comparison
- Detect file deletions
- Track and manage integrity anomalies
- Apple Photos/iPhoto library support (monitors only original files)
- JSON-based storage (no external dependencies)
- YAML configuration file (optional)
- Atomic writes to prevent database corruption
- Optional path encryption with password (-p)

## Installation

```bash
# Clone the repository
git clone https://github.com/jekil/screwedfilemonitor.git
cd screwedfilemonitor

# Optional: install PyYAML for config file support
pip install pyyaml

# Optional: install cryptography for path encryption (-p option)
pip install cryptography
```

## Usage

```bash
# Add a path to monitoring
python sfm.py -a /path/to/monitor

# Add an Apple Photos/iPhoto library (monitors only originals)
python sfm.py -a "/path/to/Photos Library.photoslibrary" --iphoto

# Run integrity check (default action)
python sfm.py

# List monitored paths
python sfm.py -l

# Remove a path from monitoring
python sfm.py -r /path/to/remove

# Show unresolved anomalies
python sfm.py --anomalies

# Show all anomalies (including resolved)
python sfm.py --all-anomalies

# Accept/resolve an anomaly by ID
python sfm.py --accept 1

# Accept/resolve all unresolved anomalies
python sfm.py --accept-all

# Enable debug output
python sfm.py -d

# Use a custom database path
python sfm.py --db /path/to/custom.json

# Ignore missing files (don't report as anomalies)
python sfm.py -i

# Encrypt file paths in database with a password
python sfm.py -p "your-secret-password"
```

## Configuration

Create a `config.yaml` file in the same directory as `sfm.py`:

```yaml
# Files to skip during scanning
skipped_files:
  - ".DS_Store"
  - "Thumbs.db"

# Directories to skip during scanning
skipped_dirs:
  - ".git"
  - "__pycache__"
  - "node_modules"

# Default database file path
db_path: "db.json"
```

If PyYAML is not installed or `config.yaml` doesn't exist, default values are used.

## Apple Photos Library Support

Use the `--iphoto` flag with `--add` to monitor an Apple Photos or iPhoto library:

```bash
python sfm.py -a "/Users/you/Pictures/Photos Library.photoslibrary" --iphoto
```

This automatically detects and monitors only the original files folder:
- `originals/` (modern Photos.app)
- `Masters/` (older Photos.app and iPhoto)

Other folders (thumbnails, previews, database) are excluded as they change frequently during normal Photos.app operation.

## Database

Data is stored in a JSON file (`db.json` by default):

```json
{
  "paths": [...],
  "files": [...],
  "hashes": [...],
  "anomalies": [...],
  "_counters": {
    "paths": 0,
    "files": 0,
    "hashes": 0,
    "anomalies": 0,
    "anomalies_accepted": 0,
    "last_anomaly_on": null,
    "saves": 0,
    "last_save_on": null
  }
}
```

A backup (`db.bak`) is created before each save.

## Security

- All database files have permissions 600 (owner read/write only)
- Atomic writes prevent corruption on interruption
- Graceful shutdown on SIGINT/SIGTERM
- Optional path encryption with `-p` flag (requires `cryptography` library)
  - Uses Fernet symmetric encryption (AES-128-CBC with HMAC)
  - Key derived from password using PBKDF2 with 480,000 iterations
  - Salt stored in database for key regeneration

## License

Copyright (C) 2014-2026 Alessandro Tanasi (@jekil)
