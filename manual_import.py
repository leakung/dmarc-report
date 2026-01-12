#!/usr/bin/env python3
"""
Manual DMARC Report Importer
Import DMARC reports from local ZIP/GZ/XML files for testing
"""

import os
import sys
import gzip
import zipfile
import glob
import argparse
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
import logging

# Add the fetcher directory to the path to import common modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'fetcher'))
from imap_fetcher import DMARCParser, DatabaseManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ManualImporter:
    """Import DMARC reports from local files"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.parser = DMARCParser()
    
    def extract_xml_from_file(self, filepath):
        """Extract XML content from a file (ZIP, GZ, or XML)"""
        logger.info(f"Processing file: {filepath}")
        
        # Handle ZIP files
        if filepath.endswith('.zip'):
            try:
                with zipfile.ZipFile(filepath, 'r') as zf:
                    xml_files = [name for name in zf.namelist() if name.endswith('.xml')]
                    if not xml_files:
                        logger.warning(f"No XML files found in {filepath}")
                        return []
                    
                    xml_contents = []
                    for xml_file in xml_files:
                        xml_content = zf.read(xml_file)
                        xml_contents.append(xml_content)
                    return xml_contents
            except Exception as e:
                logger.error(f"Error extracting ZIP {filepath}: {e}")
                return []
        
        # Handle GZIP files
        elif filepath.endswith('.gz'):
            try:
                with gzip.open(filepath, 'rb') as f:
                    return [f.read()]
            except Exception as e:
                logger.error(f"Error extracting GZIP {filepath}: {e}")
                return []
        
        # Handle XML files
        elif filepath.endswith('.xml'):
            try:
                with open(filepath, 'rb') as f:
                    return [f.read()]
            except Exception as e:
                logger.error(f"Error reading XML {filepath}: {e}")
                return []
        
        else:
            logger.warning(f"Unsupported file type: {filepath}")
            return []
    
    def import_file(self, filepath):
        """Import a single file"""
        xml_contents = self.extract_xml_from_file(filepath)
        
        imported_count = 0
        for xml_content in xml_contents:
            try:
                report_data = self.parser.parse_xml(xml_content)
                if self.db_manager.store_report(report_data):
                    imported_count += 1
                    logger.info(f"Imported report: {report_data['report_id']}")
                else:
                    logger.info(f"Report already exists: {report_data['report_id']}")
            except Exception as e:
                logger.error(f"Error parsing/storing report from {filepath}: {e}")
        
        return imported_count
    
    def import_directory(self, directory):
        """Import all DMARC reports from a directory"""
        patterns = ['*.xml', '*.zip', '*.gz']
        files = []
        
        for pattern in patterns:
            files.extend(glob.glob(os.path.join(directory, pattern)))
            files.extend(glob.glob(os.path.join(directory, '**', pattern), recursive=True))
        
        if not files:
            logger.warning(f"No DMARC report files found in {directory}")
            return 0
        
        logger.info(f"Found {len(files)} files to process")
        
        total_imported = 0
        for filepath in files:
            imported = self.import_file(filepath)
            total_imported += imported
        
        return total_imported
    
    def import_paths(self, paths):
        """Import from list of file or directory paths"""
        total_imported = 0
        
        for path in paths:
            if os.path.isfile(path):
                imported = self.import_file(path)
                total_imported += imported
            elif os.path.isdir(path):
                imported = self.import_directory(path)
                total_imported += imported
            else:
                logger.error(f"Path not found: {path}")
        
        return total_imported


def main():
    parser = argparse.ArgumentParser(
        description='Import DMARC reports from local files'
    )
    parser.add_argument(
        'paths',
        nargs='+',
        help='File or directory paths to import'
    )
    parser.add_argument(
        '--db-url',
        default=os.environ.get('DATABASE_URL'),
        help='Database URL (default: from DATABASE_URL env var)'
    )
    
    args = parser.parse_args()
    
    if not args.db_url:
        logger.error("Database URL not provided. Use --db-url or set DATABASE_URL environment variable")
        sys.exit(1)
    
    db_manager = DatabaseManager(args.db_url)
    importer = ManualImporter(db_manager)
    
    logger.info("Starting manual import")
    total_imported = importer.import_paths(args.paths)
    logger.info(f"Import complete. Total reports imported: {total_imported}")


if __name__ == '__main__':
    main()
