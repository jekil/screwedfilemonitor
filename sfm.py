#!/usr/bin/env python3
"""
Screwed File Monitor (SFM) - File Integrity Monitoring Tool

A lightweight file integrity monitoring tool that detects unauthorized
changes to files by calculating and comparing SHA-256 hashes.

Features:
    - Monitor files and directories for changes
    - Detect file modifications via hash comparison
    - Detect file deletions
    - Track and manage integrity anomalies
    - JSON-based storage (no external dependencies)

Usage:
    sfm.py -a /path/to/monitor    Add a path to monitoring
    sfm.py -r /path/to/remove     Remove a path from monitoring
    sfm.py -l                     List monitored paths
    sfm.py                        Run integrity check
    sfm.py --anomalies            Show unresolved anomalies
    sfm.py --accept ID            Accept an anomaly

Copyright (C) 2014-2026 Alessandro Tanasi (@jekil).
"""

import os
import sys
import json
import stat
import signal
import argparse
import logging
import hashlib
import tempfile
from datetime import datetime
from pathlib import Path

# File permissions: read/write for owner only (600)
FILE_PERMISSIONS = stat.S_IRUSR | stat.S_IWUSR

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# =============================================================================
# Configuration
# =============================================================================

# Version string
VERSION = "2.1.0"

# Default configuration values (used if config.yaml not found)
DEFAULT_CONFIG = {
    "skipped_files": [".DS_Store", "Thumbs.db"],
    "skipped_dirs": [".AppleDouble", ".git", "__pycache__", ".svn"],
    "db_path": "db.json"
}

# Path to configuration file (relative to script location)
CONFIG_FILE = Path(__file__).parent / "config.yaml"


def load_config():
    """
    Load configuration from YAML file.

    Falls back to DEFAULT_CONFIG if:
        - PyYAML is not installed
        - config.yaml doesn't exist
        - Error parsing config.yaml

    Returns:
        dict: Configuration dictionary.
    """
    if not YAML_AVAILABLE:
        return DEFAULT_CONFIG.copy()

    if not CONFIG_FILE.exists():
        return DEFAULT_CONFIG.copy()

    try:
        with open(CONFIG_FILE, "r") as f:
            config = yaml.safe_load(f)
            # Merge with defaults for any missing keys
            merged = DEFAULT_CONFIG.copy()
            if config:
                merged.update(config)
            return merged
    except Exception as e:
        logging.warning(f"Error loading config.yaml: {e}. Using defaults.")
        return DEFAULT_CONFIG.copy()


# Load configuration at module import
config = load_config()

# Export config values as module-level constants for convenience
SKIPPED_FILES = config["skipped_files"]
SKIPPED_DIRS = config["skipped_dirs"]
DEFAULT_DB_PATH = config["db_path"]

# Logger instance
log = logging.getLogger(__name__)


# =============================================================================
# Database Class
# =============================================================================

class Database:
    """
    Simple JSON-based database for storing monitoring data.

    Stores four collections:
        - paths: Directories/files being monitored
        - files: Individual files discovered in monitored paths
        - hashes: SHA-256 hashes for each monitored file
        - anomalies: Detected integrity violations
    """

    def __init__(self, path):
        """
        Initialize the database.

        Args:
            path: Path to the JSON database file.
        """
        self.path = Path(path)
        self._tmp_path = None  # Track temp file for cleanup on interrupt
        self.data = self._load()

    def _load(self):
        """Load database from JSON file, or create empty if not exists."""
        if self.path.exists():
            try:
                with open(self.path, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                log.error(f"Error loading database: {e}")
                return self._empty_db()
        return self._empty_db()

    def _empty_db(self):
        """Return empty database structure with all collections."""
        return {
            "paths": [],      # Monitored paths (directories or files)
            "files": [],      # Individual files found in paths
            "hashes": [],     # SHA-256 hashes for files
            "anomalies": [],  # Detected integrity violations
            "_counters": {
                "paths": 0,
                "files": 0,
                "hashes": 0,
                "anomalies": 0,
                "anomalies_accepted": 0,
                "last_anomaly_on": None,
                "saves": 0,
                "last_save_on": None
            }
        }

    def cleanup(self):
        """Remove any temporary files left over from interrupted saves."""
        if self._tmp_path and os.path.exists(self._tmp_path):
            try:
                os.unlink(self._tmp_path)
                log.debug(f"Cleaned up temporary file: {self._tmp_path}")
            except OSError:
                pass
            self._tmp_path = None

    def _set_permissions(self, path):
        """Set secure file permissions (owner read/write only)."""
        try:
            os.chmod(path, FILE_PERMISSIONS)
        except OSError:
            pass  # Ignore on systems that don't support chmod

    def save(self):
        """
        Persist database to JSON file using atomic write.

        Uses a temporary file + rename strategy to ensure the database
        is never left in a corrupted state, even if interrupted.
        All created files have permissions 600 (owner read/write only).
        """
        try:
            # Write to a temporary file in the same directory
            dir_path = self.path.parent
            fd, tmp_path = tempfile.mkstemp(suffix=".tmp", prefix="db_", dir=dir_path)
            self._tmp_path = tmp_path  # Track for cleanup on interrupt
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(self.data, f, indent=2, default=str)

                # Create backup of previous version before replacing
                if self.path.exists():
                    backup_path = self.path.with_suffix(".bak")
                    try:
                        os.replace(self.path, backup_path)
                        self._set_permissions(backup_path)
                    except OSError as e:
                        log.warning(f"Could not create backup: {e}")

                # Atomic rename (works on same filesystem)
                os.replace(tmp_path, self.path)
                self._set_permissions(self.path)
                self._tmp_path = None  # Clear after successful save
            except Exception:
                # Clean up temp file if rename fails
                self.cleanup()
                raise
        except IOError as e:
            log.error(f"Error saving database: {e}")

    def _next_id(self, collection):
        """Generate auto-incrementing ID for a collection."""
        self.data["_counters"][collection] += 1
        return self.data["_counters"][collection]

    # -------------------------------------------------------------------------
    # Path Operations
    # -------------------------------------------------------------------------

    def get_paths(self):
        """Get all monitored paths."""
        return self.data["paths"]

    def get_path_by_path(self, path):
        """Find a monitored path by its filesystem path."""
        for p in self.data["paths"]:
            if p["path"] == path:
                return p
        return None

    def add_path(self, path):
        """
        Add a new path to monitoring.

        Returns:
            The new path object, or None if already exists.
        """
        if self.get_path_by_path(path):
            return None
        new_path = {
            "id": self._next_id("paths"),
            "path": path,
            "created_on": datetime.now().isoformat()
        }
        self.data["paths"].append(new_path)
        return new_path

    def remove_path(self, path):
        """
        Remove a path and all associated files, hashes, and anomalies.

        Returns:
            True if removed, False if not found.
        """
        path_obj = self.get_path_by_path(path)
        if not path_obj:
            return False

        # Cascade delete: remove all related data
        file_ids = [f["id"] for f in self.data["files"] if f["path_id"] == path_obj["id"]]
        self.data["hashes"] = [h for h in self.data["hashes"] if h["file_id"] not in file_ids]
        self.data["anomalies"] = [a for a in self.data["anomalies"] if a["file_id"] not in file_ids]
        self.data["files"] = [f for f in self.data["files"] if f["path_id"] != path_obj["id"]]
        self.data["paths"] = [p for p in self.data["paths"] if p["id"] != path_obj["id"]]
        return True

    # -------------------------------------------------------------------------
    # File Operations
    # -------------------------------------------------------------------------

    def get_files(self):
        """Get all monitored files."""
        return self.data["files"]

    def get_file_by_path(self, path):
        """Find a monitored file by its filesystem path."""
        for f in self.data["files"]:
            if f["path"] == path:
                return f
        return None

    def get_files_by_path_id(self, path_id):
        """Get all files belonging to a monitored path."""
        return [f for f in self.data["files"] if f["path_id"] == path_id]

    def add_file(self, file_path, path_id):
        """
        Add a new file to monitoring.

        Stores file metadata: size and creation/modification time.

        Returns:
            The new file object, or None if already exists.
        """
        if self.get_file_by_path(file_path):
            return None

        # Get file metadata
        try:
            stat_info = os.stat(file_path)
            file_size = stat_info.st_size
            # Use birthtime on macOS, fallback to mtime on other platforms
            if hasattr(stat_info, 'st_birthtime'):
                file_ctime = datetime.fromtimestamp(stat_info.st_birthtime).isoformat()
            else:
                file_ctime = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            file_mtime = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
        except OSError:
            file_size = None
            file_ctime = None
            file_mtime = None

        new_file = {
            "id": self._next_id("files"),
            "path": file_path,
            "path_id": path_id,
            "size": file_size,
            "file_created_on": file_ctime,
            "file_modified_on": file_mtime,
            "created_on": datetime.now().isoformat()
        }
        self.data["files"].append(new_file)
        return new_file

    # -------------------------------------------------------------------------
    # Hash Operations
    # -------------------------------------------------------------------------

    def get_hash_by_file_id(self, file_id):
        """Get the stored hash for a file."""
        for h in self.data["hashes"]:
            if h["file_id"] == file_id:
                return h
        return None

    def add_hash(self, file_id, sha256):
        """
        Store the initial hash for a file.

        Returns:
            The new hash object, or None if already exists.
        """
        existing = self.get_hash_by_file_id(file_id)
        if existing:
            return None
        new_hash = {
            "id": self._next_id("hashes"),
            "file_id": file_id,
            "sha256": sha256,
            "created_on": datetime.now().isoformat()
        }
        self.data["hashes"].append(new_hash)
        return new_hash

    def update_hash(self, file_id, sha256):
        """
        Update the stored hash for a file (after accepting an anomaly).

        Returns:
            The updated hash object, or None if not found.
        """
        for h in self.data["hashes"]:
            if h["file_id"] == file_id:
                h["sha256"] = sha256
                return h
        return None

    def update_file_metadata(self, file_id):
        """
        Update file metadata (size and modification time) from filesystem.

        Called when accepting a hash mismatch anomaly to record the new
        file size and modification time.

        Returns:
            The updated file object, or None if not found.
        """
        for f in self.data["files"]:
            if f["id"] == file_id:
                try:
                    stat_info = os.stat(f["path"])
                    f["size"] = stat_info.st_size
                    f["file_modified_on"] = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                except OSError:
                    pass  # Keep existing values if file not accessible
                return f
        return None

    # -------------------------------------------------------------------------
    # Anomaly Operations
    # -------------------------------------------------------------------------

    def get_anomalies(self, unresolved_only=False):
        """
        Get anomalies.

        Args:
            unresolved_only: If True, only return unaccepted anomalies.
        """
        if unresolved_only:
            return [a for a in self.data["anomalies"] if a["accepted_on"] is None]
        return self.data["anomalies"]

    def get_anomaly_by_id(self, anomaly_id):
        """Find an anomaly by ID."""
        for a in self.data["anomalies"]:
            if a["id"] == anomaly_id:
                return a
        return None

    def add_anomaly(self, file_id, description, sha256=None):
        """
        Record a new integrity anomaly.

        Skips if an unresolved anomaly already exists for the same file
        with the same description.

        Args:
            file_id: ID of the affected file.
            description: Type of anomaly (e.g., "Hash mismatch", "File removed").
            sha256: New hash value (for hash mismatch anomalies).

        Returns:
            The new anomaly object, or None if duplicate unresolved anomaly exists.
        """
        # Check for existing unresolved anomaly for this file
        for a in self.data["anomalies"]:
            if (a["file_id"] == file_id and
                a["description"] == description and
                a["accepted_on"] is None):
                return None

        timestamp = datetime.now().isoformat()
        new_anomaly = {
            "id": self._next_id("anomalies"),
            "file_id": file_id,
            "description": description,
            "sha256": sha256,
            "created_on": timestamp,
            "accepted_on": None
        }
        self.data["anomalies"].append(new_anomaly)
        self.data["_counters"]["last_anomaly_on"] = timestamp
        return new_anomaly

    def accept_anomaly(self, anomaly_id):
        """
        Mark an anomaly as accepted/resolved.

        Returns:
            The updated anomaly, or None if not found.
        """
        anomaly = self.get_anomaly_by_id(anomaly_id)
        if not anomaly:
            return None
        anomaly["accepted_on"] = datetime.now().isoformat()
        self.data["_counters"]["anomalies_accepted"] += 1
        return anomaly


# =============================================================================
# Core Functions
# =============================================================================

def find_photos_library_originals(library_path):
    """
    Find the originals/masters folder in an Apple Photos or iPhoto library.

    Apple Photos libraries (.photoslibrary) store original files in:
        - 'originals/' (newer Photos.app versions)
        - 'Masters/' (older Photos.app and iPhoto)

    Only these folders contain the original, unmodified media files.
    Other folders (derivatives, thumbnails, database) change frequently
    and should not be monitored for integrity.

    Args:
        library_path: Path to the .photoslibrary bundle or iPhoto Library folder.

    Returns:
        Path to the originals folder, or None if not found.
    """
    library_path = Path(library_path).resolve()

    if not library_path.exists():
        log.error(f"Library path does not exist: {library_path}")
        return None

    # Check for modern Photos.app structure (originals/)
    originals_path = library_path / "originals"
    if originals_path.exists() and originals_path.is_dir():
        log.debug(f"Found Photos library originals at: {originals_path}")
        return str(originals_path)

    # Check for older Photos.app / iPhoto structure (Masters/)
    masters_path = library_path / "Masters"
    if masters_path.exists() and masters_path.is_dir():
        log.debug(f"Found Photos/iPhoto library masters at: {masters_path}")
        return str(masters_path)

    log.error(f"Could not find originals or Masters folder in: {library_path}")
    return None


def find_mount_point(path):
    """
    Find the mount point for a given path.

    Args:
        path: Path to check.

    Returns:
        Path object of the mount point.
    """
    path = Path(path).resolve()
    while not os.path.ismount(path):
        parent = path.parent
        if parent == path:  # Reached root
            return path
        path = parent
    return path


def is_mount_active(path):
    """
    Check if a path is on an active mount point.

    Returns False if the path is on a mount point that appears to be
    unmounted (empty directory at mount point).

    Args:
        path: Path to check.

    Returns:
        True if mount is active or path is on root filesystem.
        False if mount point appears unmounted.
    """
    path = Path(path).resolve()
    mount_point = find_mount_point(path)

    # Root filesystem is always mounted
    if mount_point == Path("/"):
        return True

    # On Windows, check if it's a drive root
    if os.name == "nt" and len(str(mount_point)) <= 3:
        return mount_point.exists()

    # Check if mount point is actually mounted by verifying it has content
    # An unmounted mount point is typically an empty directory
    try:
        # If it's a mount point and has content, it's mounted
        if os.path.ismount(mount_point):
            # Try to list directory - if empty, likely not mounted
            contents = list(mount_point.iterdir())
            if not contents:
                return False
            return True
        return False
    except PermissionError:
        # If we can't read it, assume it's mounted
        return True
    except OSError:
        return False


def calculate_hash(file_path):
    """
    Calculate SHA-256 hash for a file.

    Reads the file in chunks to handle large files efficiently.

    Args:
        file_path: Path to the file.

    Returns:
        SHA-256 hash string (64 hex characters), or None on error.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(32768)  # 32KB chunks
                if not chunk:
                    return sha256.hexdigest()
                sha256.update(chunk)
    except IOError as e:
        log.error(f"Error calculating hash on {file_path}: {e}")
        return None


def add_file_to_monitor(db, found_file, monitor_path):
    """
    Add a discovered file to the monitoring database.

    Skips files in the SKIPPED_FILES list.
    """
    if os.path.basename(found_file) in SKIPPED_FILES:
        log.debug(f"Skipping {found_file} because it's in skipped files list.")
        return

    log.debug(f"Found file: {found_file}")
    if not db.get_file_by_path(found_file):
        log.info(f"Found new file: {found_file}")
        db.add_file(found_file, monitor_path["id"])


def check_hash(db, monitored_file, file_hash):
    """
    Verify file integrity by comparing current hash with stored hash.

    If no stored hash exists, stores the current hash as baseline.
    If hash mismatch detected, creates an anomaly.
    """
    log.debug(f"Calculated hash {file_hash} for file {monitored_file['path']}")
    existing = db.get_hash_by_file_id(monitored_file["id"])

    if not existing:
        # First time seeing this file - store baseline hash
        log.debug("File not found in hash table, adding it.")
        db.add_hash(monitored_file["id"], file_hash)
    else:
        if existing["sha256"] == file_hash:
            log.debug("Hash OK")
        else:
            # Hash mismatch - file was modified!
            log.error(f"Bad hash for file: {monitored_file['path']}")
            anomaly = db.add_anomaly(monitored_file["id"], "Hash mismatch", file_hash)
            if anomaly:
                log.error(f"NEW ANOMALY [ID: {anomaly['id']}] Hash mismatch for file {monitored_file['path']} !!!")


def exist_check(db, monitored_file, ignore_not_found=False):
    """
    Verify that a monitored file still exists on the filesystem.

    If file is missing and ignore_not_found is False, creates an anomaly.

    Returns:
        True if file exists, False otherwise.
    """
    if os.path.exists(monitored_file["path"]):
        return True
    else:
        if not ignore_not_found:
            log.error(f"File {monitored_file['path']} removed.")
            anomaly = db.add_anomaly(monitored_file["id"], "File removed")
            if anomaly:
                log.error(f"NEW ANOMALY [ID: {anomaly['id']}] File removed: {monitored_file['path']} !!!")
        return False


# =============================================================================
# CLI Commands
# =============================================================================

def cmd_add_path(db, path):
    """Add a filesystem path to monitoring."""
    if not os.path.exists(path):
        log.error("You are trying to add a non-existent path.")
        return False

    abs_path = os.path.abspath(path)
    if db.add_path(abs_path):
        log.info(f"Added path: {abs_path}")
        db.save()
        return True
    else:
        log.error("The path is already monitored.")
        return False


def cmd_remove_path(db, path):
    """Remove a path from monitoring (cascades to files and hashes)."""
    abs_path = os.path.abspath(path)
    if db.remove_path(abs_path):
        log.info(f"Removed path: {abs_path}")
        db.save()
        return True
    else:
        log.error(f"Path not found: {abs_path}")
        return False


def cmd_list_paths(db):
    """Display all monitored paths with file counts."""
    paths = db.get_paths()
    if not paths:
        print("No monitored paths configured.")
        return
    print("Monitored paths:")
    for p in paths:
        file_count = len(db.get_files_by_path_id(p["id"]))
        print(f"  [{p['id']}] {p['path']} ({file_count} files)")


def cmd_list_anomalies(db, unresolved_only=True):
    """Display anomalies (integrity violations)."""
    anomalies = db.get_anomalies(unresolved_only)

    if not anomalies:
        print("No anomalies found." if not unresolved_only else "No unresolved anomalies.")
        return

    status = "unresolved " if unresolved_only else ""
    print(f"Found {len(anomalies)} {status}anomalies:")
    for a in anomalies:
        status_str = "RESOLVED" if a["accepted_on"] else "UNRESOLVED"
        file_obj = next((f for f in db.get_files() if f["id"] == a["file_id"]), None)
        file_path = file_obj["path"] if file_obj else "Unknown"
        print(f"  [{a['id']}] [{status_str}] {a['description']}: {file_path}")
        if a["sha256"]:
            print(f"         New hash: {a['sha256']}")


def cmd_accept_anomaly(db, anomaly_id):
    """
    Accept an anomaly as legitimate change.

    For hash mismatch anomalies, also updates the stored hash
    to the new value so future checks won't flag it again.
    """
    anomaly = db.get_anomaly_by_id(anomaly_id)
    if not anomaly:
        log.error(f"Anomaly {anomaly_id} not found.")
        return False

    if anomaly["accepted_on"]:
        log.warning(f"Anomaly {anomaly_id} already accepted.")
        return False

    db.accept_anomaly(anomaly_id)

    # For hash mismatches, update the baseline hash and file metadata
    if anomaly["sha256"] and anomaly["description"] == "Hash mismatch":
        db.update_hash(anomaly["file_id"], anomaly["sha256"])
        db.update_file_metadata(anomaly["file_id"])
        file_obj = next((f for f in db.get_files() if f["id"] == anomaly["file_id"]), None)
        if file_obj:
            log.info(f"Updated hash for {file_obj['path']}")

    log.info(f"Accepted anomaly {anomaly_id}")
    db.save()
    return True


def cmd_accept_all_anomalies(db):
    """Accept all unresolved anomalies."""
    anomalies = db.get_anomalies(unresolved_only=True)

    if not anomalies:
        log.info("No unresolved anomalies to accept.")
        return False

    count = 0
    for anomaly in anomalies:
        db.accept_anomaly(anomaly["id"])

        # For hash mismatches, update the baseline hash and file metadata
        if anomaly["sha256"] and anomaly["description"] == "Hash mismatch":
            db.update_hash(anomaly["file_id"], anomaly["sha256"])
            db.update_file_metadata(anomaly["file_id"])

        count += 1

    db.save()
    log.info(f"Accepted {count} anomalies.")
    return True


def cmd_run(db, ignore_not_found=False):
    """
    Run the integrity check scan.

    1. Walks all monitored paths discovering files
    2. For each file, calculates current hash
    3. Compares with stored hash to detect modifications
    4. Reports any anomalies found
    """
    paths = db.get_paths()

    if not paths:
        log.warning("No paths configured. Use --add to add paths to monitor.")
        return

    # Update save counter
    db.data["_counters"]["saves"] += 1
    db.data["_counters"]["last_save_on"] = datetime.now().isoformat()

    # Phase 1: Discover files in all monitored paths
    for monitor_path in paths:
        # Check if mount point is active (for paths on external/network drives)
        if not is_mount_active(monitor_path["path"]):
            log.warning(f"Skipping {monitor_path['path']}: mount point not active")
            continue

        if not os.path.exists(monitor_path["path"]):
            log.warning(f"Configured path {monitor_path['path']} doesn't exist.")
        elif os.path.isdir(monitor_path["path"]):
            if os.path.basename(monitor_path["path"]) in SKIPPED_DIRS:
                log.debug(f"Skipping directory: {monitor_path['path']} (in ignore list)")
            else:
                log.debug(f"Scanning directory: {monitor_path['path']}")
                for root, dirs, files in os.walk(monitor_path["path"], onerror=log.error):
                    # Filter out skipped directories to prevent descending into them
                    dirs[:] = [d for d in dirs if d not in SKIPPED_DIRS]
                    for f in sorted(files):
                        found_file = os.path.join(root, f)
                        add_file_to_monitor(db, found_file, monitor_path)
        elif os.path.isfile(monitor_path["path"]):
            add_file_to_monitor(db, monitor_path["path"], monitor_path)

    # Phase 2: Verify integrity of all monitored files
    for monitored_file in db.get_files():
        # Skip files on unmounted volumes
        if not is_mount_active(monitored_file["path"]):
            log.debug(f"Skipping {monitored_file['path']}: mount not active")
            continue

        if exist_check(db, monitored_file, ignore_not_found):
            file_hash = calculate_hash(monitored_file["path"])
            if file_hash:
                check_hash(db, monitored_file, file_hash)
            else:
                log.warning(f"Could not calculate hash for {monitored_file['path']}")

    # Save all changes at the end
    db.save()


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Parse arguments and execute the appropriate command."""
    parser = argparse.ArgumentParser(
        description="Screwed File Monitor - File integrity monitoring tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-a", "--add", metavar="PATH",
                        help="Add a path to monitoring")
    parser.add_argument("--iphoto", action="store_true",
                        help="Treat path as Photos/iPhoto library (use with --add)")
    parser.add_argument("-r", "--remove", metavar="PATH",
                        help="Remove a path from monitoring")
    parser.add_argument("-l", "--list", action="store_true",
                        help="List monitored paths")
    parser.add_argument("--anomalies", action="store_true",
                        help="List unresolved anomalies")
    parser.add_argument("--all-anomalies", action="store_true",
                        help="List all anomalies (including resolved)")
    parser.add_argument("--accept", metavar="ID", type=int,
                        help="Accept/resolve an anomaly by ID")
    parser.add_argument("--accept-all", action="store_true",
                        help="Accept/resolve all unresolved anomalies")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Display debug messages")
    parser.add_argument("-i", "--ignore-not-found", action="store_true",
                        help="Don't raise errors for missing files")
    parser.add_argument("--db", metavar="PATH", default=DEFAULT_DB_PATH,
                        help=f"Database path (default: {DEFAULT_DB_PATH})")
    parser.add_argument("-v", "--version", action="version",
                        version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    # Configure logging level based on debug flag
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s - %(message)s"
    )

    log.debug(f"Screwed File Monitor v{VERSION} starting...")
    log.debug(f"Using database: {args.db}")

    # Initialize database connection
    db = Database(args.db)

    # Setup signal handler for graceful shutdown on Ctrl+C
    def signal_handler(_signum, _frame):
        """Handle interrupt signal by cleaning up and exiting cleanly."""
        log.warning("\nInterrupted! Cleaning up...")
        db.cleanup()  # Remove any temp files from interrupted save
        log.info("Cleanup complete. Exiting.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Check for invalid option combinations
    if args.iphoto and not args.add:
        log.error("--iphoto requires --add")
        sys.exit(1)

    # Route to appropriate command handler
    if args.add:
        path_to_add = args.add
        if args.iphoto:
            # Find the originals folder in the Photos/iPhoto library
            originals = find_photos_library_originals(args.add)
            if not originals:
                log.error("Failed to find originals in Photos library.")
                sys.exit(1)
            path_to_add = originals
            log.info(f"Adding Photos library originals: {path_to_add}")
        cmd_add_path(db, path_to_add)
    elif args.remove:
        cmd_remove_path(db, args.remove)
    elif args.list:
        cmd_list_paths(db)
    elif args.anomalies:
        cmd_list_anomalies(db, unresolved_only=True)
    elif args.all_anomalies:
        cmd_list_anomalies(db, unresolved_only=False)
    elif args.accept:
        cmd_accept_anomaly(db, args.accept)
    elif args.accept_all:
        cmd_accept_all_anomalies(db)
    else:
        # Default action: run integrity scan
        cmd_run(db, args.ignore_not_found)


if __name__ == "__main__":
    main()
