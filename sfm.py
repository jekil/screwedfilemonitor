#!/usr/bin/env python3
# Copyright (C) 2014-2024 Alessandro Tanasi (@jekil).

import os
import sys
import argparse
import logging
import hashlib
from datetime import datetime
from contextlib import contextmanager

try:
    from sqlalchemy import (
        create_engine, Column, Integer, String, DateTime, Text, ForeignKey
    )
    from sqlalchemy.orm import (
        declarative_base, sessionmaker, relationship, backref
    )
    from sqlalchemy.exc import IntegrityError
except ImportError:
    print("SQLAlchemy not found, please install it. (For example with: `pip install sqlalchemy`)")
    sys.exit(1)

# List of files skipped (i.e. system files, index files).
SKIPPED_FILES = [".DS_Store", "Thumbs.db"]
SKIPPED_DIRS = [".AppleDouble", ".git", "__pycache__", ".svn"]

VERSION = "2.0.0"
DEFAULT_DB_PATH = "sqlite:///db.sqlite"

Base = declarative_base()
log = logging.getLogger(__name__)


class MonitoredPath(Base):
    """Which paths have to be monitored."""

    __tablename__ = "monitored_paths"

    id = Column(Integer, primary_key=True)
    path = Column(String(255), nullable=False, unique=True)
    created_on = Column(DateTime(timezone=False), default=datetime.now, nullable=False)

    def __repr__(self):
        return f"<MonitoredPath(path='{self.path}')>"


class MonitoredFile(Base):
    """Monitored files."""

    __tablename__ = "monitored_files"

    id = Column(Integer, primary_key=True)
    path = Column(String(255), nullable=False, unique=True)
    monitored_path_id = Column(Integer, ForeignKey("monitored_paths.id"))
    monitored_path = relationship(
        "MonitoredPath",
        backref=backref("monitored_files", order_by=id),
        cascade="all, delete, delete-orphan",
        single_parent=True
    )
    created_on = Column(DateTime(timezone=False), default=datetime.now, nullable=False)

    def __repr__(self):
        return f"<MonitoredFile(path='{self.path}')>"


class FileHash(Base):
    """Calculated file's hash."""

    __tablename__ = "file_hashes"

    id = Column(Integer, primary_key=True)
    sha256 = Column(String(64), nullable=False)
    monitored_file_id = Column(Integer, ForeignKey("monitored_files.id"))
    monitored_file = relationship(
        "MonitoredFile",
        backref=backref("hashes", order_by=id),
        cascade="all, delete, delete-orphan",
        single_parent=True
    )
    created_on = Column(DateTime(timezone=False), default=datetime.now, nullable=False)

    def __repr__(self):
        return f"<FileHash(sha256='{self.sha256}')>"


class Anomaly(Base):
    """File's integrity violation."""

    __tablename__ = "file_anomalies"

    id = Column(Integer, primary_key=True)
    description = Column(Text(), nullable=False)
    sha256 = Column(String(64), nullable=True)
    monitored_file_id = Column(Integer, ForeignKey("monitored_files.id"))
    monitored_file = relationship("MonitoredFile", single_parent=True)
    created_on = Column(DateTime(timezone=False), default=datetime.now, nullable=False)
    accepted_on = Column(DateTime(timezone=False), nullable=True)

    def __repr__(self):
        return f"<Anomaly(description='{self.description}')>"


@contextmanager
def get_session(Session):
    """Context manager for database sessions."""
    session = Session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def calculate_hash(file_path):
    """Calculate SHA-256 hash for a file.

    Args:
        file_path: Path to the file.

    Returns:
        SHA-256 hash string, or None if an error occurred.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(32768)
                if not chunk:
                    return sha256.hexdigest()
                sha256.update(chunk)
    except IOError as e:
        log.error(f"Error calculating hash on {file_path}: {e}")
        return None


def add_file_to_monitor(session, found_file, monitor_path):
    """Adds a file to integrity monitoring.

    Args:
        session: Database session.
        found_file: File path to add.
        monitor_path: Parent MonitoredPath object.
    """
    if os.path.basename(found_file) in SKIPPED_FILES:
        log.debug(f"Skipping {found_file} because it's in skipped files list.")
        return

    log.debug(f"Found file: {found_file}")
    if not session.query(MonitoredFile).filter(MonitoredFile.path == found_file).count():
        log.info(f"Found new file: {found_file}")
        mf = MonitoredFile(path=found_file, monitored_path=monitor_path)
        session.add(mf)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            log.debug("The file is already monitored.")
        except Exception as e:
            session.rollback()
            log.error(f"Error adding file: {e}")


def add_hash(session, monitored_file, file_hash):
    """Stores a file hash.

    Args:
        session: Database session.
        monitored_file: MonitoredFile object.
        file_hash: SHA-256 hash string.
    """
    log.debug(f"Calculated hash {file_hash} for file {monitored_file.path}")
    existing = session.query(FileHash).filter(FileHash.monitored_file == monitored_file).first()

    if not existing:
        log.debug("File not found in hash table, adding it.")
        fh = FileHash(sha256=file_hash, monitored_file=monitored_file)
        session.add(fh)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            log.debug("The file hash already exists.")
        except Exception as e:
            session.rollback()
            log.error(f"Error adding hash: {e}")
    else:
        if existing.sha256 == file_hash:
            log.debug("Hash OK")
        else:
            log.error(f"Bad hash for file: {monitored_file.path}")
            add_anomaly(session, "Hash mismatch", monitored_file, file_hash)


def exist_check(session, monitored_file, ignore_not_found=False):
    """Check if a file exists.

    Args:
        session: Database session.
        monitored_file: MonitoredFile object.
        ignore_not_found: If True, don't log errors for missing files.

    Returns:
        True if file exists, False otherwise.
    """
    if os.path.exists(monitored_file.path):
        return True
    else:
        if not ignore_not_found:
            log.error(f"File {monitored_file.path} removed.")
            add_anomaly(session, "File removed", monitored_file)
        return False


def add_anomaly(session, description, monitored_file, sha256=None):
    """Add an anomaly.

    Args:
        session: Database session.
        description: Anomaly description.
        monitored_file: MonitoredFile object.
        sha256: File hash (optional).
    """
    ano = Anomaly(description=description, monitored_file=monitored_file, sha256=sha256)
    session.add(ano)
    try:
        session.commit()
        log.error(f"NEW ANOMALY [ID: {ano.id}] {ano.description} for file {ano.monitored_file.path} !!!")
    except Exception as e:
        session.rollback()
        log.error(f"Error adding anomaly: {e}")


def cmd_add_path(Session, path):
    """Add a path to monitoring."""
    if not os.path.exists(path):
        log.error("You are trying to add a non-existent path.")
        return False

    with get_session(Session) as session:
        new_path = MonitoredPath(path=os.path.abspath(path))
        session.add(new_path)
        try:
            session.commit()
            log.info(f"Added path: {path}")
            return True
        except IntegrityError:
            session.rollback()
            log.error("The path is already monitored.")
            return False


def cmd_remove_path(Session, path):
    """Remove a path from monitoring."""
    with get_session(Session) as session:
        monitored = session.query(MonitoredPath).filter(MonitoredPath.path == os.path.abspath(path)).first()
        if monitored:
            session.delete(monitored)
            session.commit()
            log.info(f"Removed path: {path}")
            return True
        else:
            log.error(f"Path not found: {path}")
            return False


def cmd_list_paths(Session):
    """List all monitored paths."""
    with get_session(Session) as session:
        paths = session.query(MonitoredPath).all()
        if not paths:
            print("No monitored paths configured.")
            return
        print("Monitored paths:")
        for p in paths:
            file_count = session.query(MonitoredFile).filter(MonitoredFile.monitored_path_id == p.id).count()
            print(f"  [{p.id}] {p.path} ({file_count} files)")


def cmd_list_anomalies(Session, unresolved_only=True):
    """List anomalies."""
    with get_session(Session) as session:
        query = session.query(Anomaly)
        if unresolved_only:
            query = query.filter(Anomaly.accepted_on.is_(None))
        anomalies = query.all()

        if not anomalies:
            print("No anomalies found." if not unresolved_only else "No unresolved anomalies.")
            return

        status = "unresolved " if unresolved_only else ""
        print(f"Found {len(anomalies)} {status}anomalies:")
        for a in anomalies:
            status_str = "RESOLVED" if a.accepted_on else "UNRESOLVED"
            print(f"  [{a.id}] [{status_str}] {a.description}: {a.monitored_file.path}")
            if a.sha256:
                print(f"         New hash: {a.sha256}")


def cmd_accept_anomaly(Session, anomaly_id):
    """Accept/resolve an anomaly and update the stored hash."""
    with get_session(Session) as session:
        anomaly = session.query(Anomaly).filter(Anomaly.id == anomaly_id).first()
        if not anomaly:
            log.error(f"Anomaly {anomaly_id} not found.")
            return False

        if anomaly.accepted_on:
            log.warning(f"Anomaly {anomaly_id} already accepted.")
            return False

        anomaly.accepted_on = datetime.now()

        # If it's a hash mismatch, update the stored hash
        if anomaly.sha256 and anomaly.description == "Hash mismatch":
            file_hash = session.query(FileHash).filter(
                FileHash.monitored_file_id == anomaly.monitored_file_id
            ).first()
            if file_hash:
                file_hash.sha256 = anomaly.sha256
                log.info(f"Updated hash for {anomaly.monitored_file.path}")

        session.commit()
        log.info(f"Accepted anomaly {anomaly_id}")
        return True


def cmd_run(Session, ignore_not_found=False):
    """Run the integrity check."""
    with get_session(Session) as session:
        paths = session.query(MonitoredPath).all()

        if not paths:
            log.warning("No paths configured. Use --add to add paths to monitor.")
            return

        for monitor_path in paths:
            if not os.path.exists(monitor_path.path):
                log.warning(f"Configured path {monitor_path.path} doesn't exist.")
            elif os.path.isdir(monitor_path.path):
                if os.path.basename(monitor_path.path) in SKIPPED_DIRS:
                    log.debug(f"Skipping directory: {monitor_path.path} (in ignore list)")
                else:
                    log.debug(f"Scanning directory: {monitor_path.path}")
                    for root, dirs, files in os.walk(monitor_path.path, onerror=log.error):
                        # Filter out skipped directories in-place
                        dirs[:] = [d for d in dirs if d not in SKIPPED_DIRS]
                        for f in sorted(files):
                            found_file = os.path.join(root, f)
                            add_file_to_monitor(session, found_file, monitor_path)
            elif os.path.isfile(monitor_path.path):
                add_file_to_monitor(session, monitor_path.path, monitor_path)

        # Calculate and verify hashes
        for monitored_file in session.query(MonitoredFile):
            if exist_check(session, monitored_file, ignore_not_found):
                file_hash = calculate_hash(monitored_file.path)
                if file_hash:
                    add_hash(session, monitored_file, file_hash)
                else:
                    log.warning(f"Could not calculate hash for {monitored_file.path}")


def main():
    parser = argparse.ArgumentParser(
        description="Screwed File Monitor - File integrity monitoring tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-a", "--add", metavar="PATH",
                        help="Add a path to monitoring")
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
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Display debug messages")
    parser.add_argument("-i", "--ignore-not-found", action="store_true",
                        help="Don't raise errors for missing files")
    parser.add_argument("--db", metavar="PATH", default=DEFAULT_DB_PATH,
                        help=f"Database path (default: {DEFAULT_DB_PATH})")
    parser.add_argument("-v", "--version", action="version",
                        version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s - %(message)s"
    )

    log.debug(f"Screwed File Monitor v{VERSION} starting...")
    log.debug(f"Using database: {args.db}")

    # Initialize database
    engine = create_engine(args.db, echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    # Execute commands
    if args.add:
        cmd_add_path(Session, args.add)
    elif args.remove:
        cmd_remove_path(Session, args.remove)
    elif args.list:
        cmd_list_paths(Session)
    elif args.anomalies:
        cmd_list_anomalies(Session, unresolved_only=True)
    elif args.all_anomalies:
        cmd_list_anomalies(Session, unresolved_only=False)
    elif args.accept:
        cmd_accept_anomaly(Session, args.accept)
    else:
        cmd_run(Session, args.ignore_not_found)


if __name__ == "__main__":
    main()
