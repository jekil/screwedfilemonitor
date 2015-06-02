#! /usr/bin/env python
# Copyright (C) 2014 Alessandro Tanasi (@jekil).

import os
import sys
import argparse
import logging
import hashlib
from datetime import datetime

try:
    from sqlalchemy import create_engine
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy import Column, Integer, String, DateTime, Text
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import ForeignKey
    from sqlalchemy.orm import relationship, backref
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.sql import exists
except ImportError:
    print "SQLAlchemy not found, please install it. (For example with: `pip install sqlalchemy`"
    sys.exit(1)

# List of files skipped (i.e. system files, index files).
SKIPPED_FILES = [".DS_Store", "Thumbs.db"]

Base = declarative_base()
log = logging.getLogger("")


class MonitoredPath(Base):
    """Which paths have to be monitored."""

    __tablename__ = "monitored_paths"

    id = Column(Integer, primary_key=True)
    path = Column(String(255), nullable=False, unique=True)
    created_on = Column(DateTime(timezone=False),
                        default=datetime.now,
                        nullable=False)

    def __repr__(self):
        return "<MonitoredPath(path='%s'>" % self.path


class MonitoredFile(Base):
    """Monitored files."""

    __tablename__ = "monitored_files"

    id = Column(Integer, primary_key=True)
    path = Column(String(255), nullable=False, unique=True)
    monitored_path_id = Column(Integer, ForeignKey("monitored_paths.id"))
    monitored_path = relationship("MonitoredPath", backref=backref("monitored_files", order_by=id), cascade="all, delete, delete-orphan", single_parent=True)
    created_on = Column(DateTime(timezone=False),
                        default=datetime.now,
                        nullable=False)

    def __repr__(self):
        return "<MonitoredFile(path='%s'>" % self.path


class FileHash(Base):
    """Calculated file's hash."""

    __tablename__ = "file_hashes"

    id = Column(Integer, primary_key=True)
    md5 = Column(String(32), nullable=False)
    monitored_file_id = Column(Integer, ForeignKey("monitored_files.id"))
    monitored_file = relationship("MonitoredFile", backref=backref("hashes", order_by=id), cascade="all, delete, delete-orphan", single_parent=True)
    created_on = Column(DateTime(timezone=False),
                        default=datetime.now,
                        nullable=False)

    def __repr__(self):
        return "<FileHash(path='%s'>" % self.md5


class Anomaly(Base):
    """File's integrity violation."""

    __tablename__ = "file_anomalies"

    id = Column(Integer, primary_key=True)
    description = Column(Text(), nullable=False)
    md5 = Column(String(32), nullable=True)
    monitored_file_id = Column(Integer, ForeignKey("monitored_files.id"))
    monitored_file = relationship("MonitoredFile", single_parent=True)
    created_on = Column(DateTime(timezone=False),
                        default=datetime.now,
                        nullable=False)
    accepted_on = Column(DateTime(timezone=False), nullable=True)

    def __repr__(self):
        return "<Anomaly(description='%s'>" % self.description


def calculate_hash(file):
    """Calculate MD5 for a file.
    @param file: file path
    @returns: MD5 string
    """
    md5 = hashlib.md5()
    try:
        with open(file, "rb") as f:
            while True:
                chunk = f.read(32768)
                md5.update(chunk)
                if not chunk:
                    return md5.hexdigest()
    except IOError, e:
        log.error("Error calculating hash on %s: %s" % (file, e))


def add_file_to_monitor(found_file):
    # Skip check if file name is in blacklist. (i.e. dynamic files like Thumbs.db)
    if os.path.basename(found_file) in SKIPPED_FILES:
        logging.debug("Skipping %s because of in skipped files list." % found_file)
        return

    logging.debug("Found file: %s" % found_file)
    if not session.query(MonitoredFile).filter(MonitoredFile.path==found_file).count():
        logging.info("Found new file: %s" % found_file)
        mf = MonitoredFile(path=found_file, monitored_path=monitor_path)
        session.add(mf)
        try:
            session.commit()
        except IntegrityError:
            logging.debug("The file is already monitored.")
        except Exception as e:
            session.rollback()
            logging.error("Error adding file: %s" % e)

def add_hash(monitored_file, file_hash):
    logging.debug("Calculated hash %s for file %s" % (file_hash, monitored_file.path))
    if not session.query(FileHash).filter(FileHash.monitored_file==monitored_file).count():
        logging.debug("File not found in hash table, adding it.")
        mf = FileHash(md5=file_hash, monitored_file=monitored_file)
        session.add(mf)
        try:
            session.commit()
        except IntegrityError:
            logging.debug("The file is already monitored.")
        except Exception as e:
            session.rollback()
            logging.error("Error adding file: %s" % e)
    else:
        original_hash = session.query(FileHash).filter(FileHash.monitored_file==monitored_file).one()
        if original_hash.md5 == file_hash:
            logging.debug("Hash OK")
        else:
            logging.error("Bad hash for file: %s" % monitored_file.path)
            add_anomaly("Hash mismatch", monitored_file, file_hash)

def exist_check(monitored_file):
    if os.path.exists(monitored_file.path):
        return True
    else:
        if not args.ignore_not_found:
            logging.error("File %s removed." % monitored_file.path)
            add_anomaly("File removed", monitored_file)
        return False

def add_anomaly(description, monitored_file, md5=None):
    ano = Anomaly(description=description, monitored_file=monitored_file, md5=md5)
    session.add(ano)
    try:
        session.commit()
    except Exception as e:
        session.rollback()
        logging.error("Error adding anaomaly: %s" % e)

    logging.error("NEW ANOMALY [ID: %s] %s for file %s !!!" % (ano.id, ano.description, ano.monitored_file.path))



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--add", help="Add a path to monitoring", type=str, required=False)
    parser.add_argument("-d", "--debug", help="Display debug messages", action="store_true", required=False)
    parser.add_argument("-i", "--ignore-not-found", help="Don't raise errors for not found files", action="store_true", required=False)
    args = parser.parse_args()

    # Logging level.
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(level=log_level, format="%(levelname)s - %(message)s")

    engine = create_engine("sqlite:///db.sqlite", echo=False)

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    # Adding.
    if args.add:
        if os.path.exists(args.add):
            session = Session()
            new_path = MonitoredPath(path=args.add)
            session.add(new_path)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                logging.error("The path is aldready monitored.")
            finally:
                session.close()
        else:
            logging.error("You are trying to add a not existant path.")
    else:
        # Run.
        session = Session()
        paths = session.query(MonitoredPath)

        for monitor_path in paths:
            if not os.path.exists(monitor_path.path):
                logging.warning("Configured path %s doesn't exist." % monitor_path.path)
            elif os.path.isdir(monitor_path.path):
                logging.debug("Adding directory: %s" % monitor_path.path)
                for root, dirs, files in os.walk(monitor_path.path, onerror=logging.error):
                    for f in sorted(files):
                        found_file = os.path.join(root, f)
                        add_file_to_monitor(found_file)
            elif os.path.isfile(monitor_path.path):
                add_file_to_monitor(monitor_path.path)

        # Calculating hashes.
        for monitored_file in session.query(MonitoredFile):
            if exist_check(monitored_file):
                file_hash = calculate_hash(monitored_file.path)
                add_hash(monitored_file, file_hash)
