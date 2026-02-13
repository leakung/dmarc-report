#!/usr/bin/env python3
"""
IMAP DMARC Report Fetcher
Connects to IMAP server, fetches DMARC reports, and stores them in PostgreSQL
"""

import imaplib
import email
from email import policy
import os
import time
import gzip
import zipfile
import io
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DMARCParser:
    """Parse DMARC XML reports and extract data"""
    
    def parse_xml(self, xml_content):
        """Parse DMARC XML and return structured data"""
        try:
            root = ET.fromstring(xml_content)
            
            # Extract report metadata
            report_metadata = root.find('report_metadata')
            org_name = self._get_text(report_metadata, 'org_name')
            email = self._get_text(report_metadata, 'email')
            extra_contact = self._get_text(report_metadata, 'extra_contact_info')
            report_id = self._get_text(report_metadata, 'report_id')
            
            date_range = report_metadata.find('date_range')
            begin = datetime.fromtimestamp(int(self._get_text(date_range, 'begin')))
            end = datetime.fromtimestamp(int(self._get_text(date_range, 'end')))
            
            # Extract policy published
            policy_pub = root.find('policy_published')
            domain = self._get_text(policy_pub, 'domain')
            adkim = self._get_text(policy_pub, 'adkim', 'r')
            aspf = self._get_text(policy_pub, 'aspf', 'r')
            p = self._get_text(policy_pub, 'p')
            sp = self._get_text(policy_pub, 'sp', p)
            pct = int(self._get_text(policy_pub, 'pct', '100'))
            
            report_data = {
                'org_name': org_name,
                'email': email,
                'extra_contact_info': extra_contact,
                'report_id': report_id,
                'date_range_begin': begin,
                'date_range_end': end,
                'domain': domain,
                'adkim': adkim,
                'aspf': aspf,
                'p': p,
                'sp': sp,
                'pct': pct,
                'raw_xml': xml_content.decode('utf-8') if isinstance(xml_content, bytes) else xml_content
            }
            
            # Extract records
            records = []
            for record in root.findall('record'):
                row = record.find('row')
                source_ip = self._get_text(row, 'source_ip')
                count = int(self._get_text(row, 'count', '0'))
                
                policy_evaluated = row.find('policy_evaluated')
                disposition = self._get_text(policy_evaluated, 'disposition')
                dkim_result = self._get_text(policy_evaluated, 'dkim')
                spf_result = self._get_text(policy_evaluated, 'spf')
                
                identifiers = record.find('identifiers')
                header_from = self._get_text(identifiers, 'header_from')
                envelope_from = self._get_text(identifiers, 'envelope_from', header_from)
                envelope_to = self._get_text(identifiers, 'envelope_to', '')
                
                record_data = {
                    'source_ip': source_ip,
                    'count': count,
                    'disposition': disposition,
                    'dkim_result': dkim_result,
                    'spf_result': spf_result,
                    'header_from': header_from,
                    'envelope_from': envelope_from,
                    'envelope_to': envelope_to
                }
                
                # Extract DKIM auth results
                dkim_auths = []
                auth_results = record.find('auth_results')
                if auth_results:
                    for dkim in auth_results.findall('dkim'):
                        dkim_auths.append({
                            'domain': self._get_text(dkim, 'domain'),
                            'selector': self._get_text(dkim, 'selector'),
                            'result': self._get_text(dkim, 'result'),
                            'human_result': self._get_text(dkim, 'human_result', '')
                        })
                    
                    # Extract SPF auth results
                    spf_auths = []
                    for spf in auth_results.findall('spf'):
                        spf_auths.append({
                            'domain': self._get_text(spf, 'domain'),
                            'scope': self._get_text(spf, 'scope', 'mfrom'),
                            'result': self._get_text(spf, 'result')
                        })
                    
                    record_data['dkim_auths'] = dkim_auths
                    record_data['spf_auths'] = spf_auths
                
                records.append(record_data)
            
            report_data['records'] = records
            return report_data
            
        except Exception as e:
            logger.error(f"Error parsing XML: {e}")
            raise
    
    def _get_text(self, element, tag, default=''):
        """Safely extract text from XML element"""
        if element is None:
            return default
        child = element.find(tag)
        if child is not None and child.text:
            return child.text
        return default


class DatabaseManager:
    """Manage database connections and operations"""
    
    def __init__(self, db_url):
        self.db_url = db_url
    
    def get_connection(self):
        """Get database connection"""
        return psycopg2.connect(self.db_url)
    
    def store_report(self, report_data):
        """Store parsed DMARC report in database"""
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Check if report already exists
                cur.execute(
                    "SELECT id FROM reports WHERE report_id = %s",
                    (report_data['report_id'],)
                )
                if cur.fetchone():
                    logger.info(f"Report {report_data['report_id']} already exists, skipping")
                    return False
                
                # Insert report
                cur.execute("""
                    INSERT INTO reports (
                        org_name, email, extra_contact_info, report_id,
                        date_range_begin, date_range_end, domain,
                        adkim, aspf, p, sp, pct, raw_xml
                    ) VALUES (
                        %(org_name)s, %(email)s, %(extra_contact_info)s, %(report_id)s,
                        %(date_range_begin)s, %(date_range_end)s, %(domain)s,
                        %(adkim)s, %(aspf)s, %(p)s, %(sp)s, %(pct)s, %(raw_xml)s
                    ) RETURNING id
                """, report_data)
                
                report_id = cur.fetchone()['id']
                
                # Insert records
                for record in report_data['records']:
                    cur.execute("""
                        INSERT INTO records (
                            report_id, source_ip, count, disposition,
                            dkim_result, spf_result, header_from,
                            envelope_from, envelope_to
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s
                        ) RETURNING id
                    """, (
                        report_id, record['source_ip'], record['count'],
                        record['disposition'], record['dkim_result'],
                        record['spf_result'], record['header_from'],
                        record['envelope_from'], record['envelope_to']
                    ))
                    
                    record_id = cur.fetchone()['id']
                    
                    # Insert DKIM auth results
                    for dkim in record.get('dkim_auths', []):
                        cur.execute("""
                            INSERT INTO dkim_auth (
                                record_id, domain, selector, result, human_result
                            ) VALUES (%s, %s, %s, %s, %s)
                        """, (
                            record_id, dkim['domain'], dkim['selector'],
                            dkim['result'], dkim['human_result']
                        ))
                    
                    # Insert SPF auth results
                    for spf in record.get('spf_auths', []):
                        cur.execute("""
                            INSERT INTO spf_auth (
                                record_id, domain, scope, result
                            ) VALUES (%s, %s, %s, %s)
                        """, (record_id, spf['domain'], spf['scope'], spf['result']))
                
                conn.commit()
                logger.info(f"Successfully stored report {report_data['report_id']}")
                return True
                
        except Exception as e:
            conn.rollback()
            logger.error(f"Error storing report: {e}")
            raise
        finally:
            conn.close()
    
    def mark_email_processed(self, message_id, subject, source='imap'):
        """Mark an email as processed"""
        conn = self.get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO processed_emails (message_id, subject, source)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (message_id) DO NOTHING
                """, (message_id, subject, source))
                conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Error marking email as processed: {e}")
        finally:
            conn.close()
    
    def is_email_processed(self, message_id):
        """Check if email has been processed"""
        conn = self.get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM processed_emails WHERE message_id = %s",
                    (message_id,)
                )
                return cur.fetchone() is not None
        finally:
            conn.close()


class IMAPFetcher:
    """Fetch DMARC reports from IMAP server"""
    
    def __init__(self, server, port, user, password, folder='INBOX', days_limit=None):
        self.server = server
        self.port = port
        self.user = user
        self.password = password
        self.folder = folder
        self.days_limit = days_limit
        self.parser = DMARCParser()
    
    def connect(self):
        """Connect to IMAP server"""
        logger.info(f"Connecting to {self.server}:{self.port}")
        mail = imaplib.IMAP4_SSL(self.server, self.port)
        mail.login(self.user, self.password)
        mail.select(self.folder)
        return mail
    
    def extract_xml_from_attachment(self, part):
        """Extract XML content from email attachment"""
        filename = part.get_filename()
        if not filename:
            return None
        
        content = part.get_payload(decode=True)
        
        # Handle ZIP files
        if filename.endswith('.zip'):
            try:
                with zipfile.ZipFile(io.BytesIO(content)) as zf:
                    for name in zf.namelist():
                        if name.endswith('.xml'):
                            return zf.read(name)
            except Exception as e:
                logger.error(f"Error extracting ZIP: {e}")
                return None
        
        # Handle GZIP files
        elif filename.endswith('.gz'):
            try:
                return gzip.decompress(content)
            except Exception as e:
                logger.error(f"Error extracting GZIP: {e}")
                return None
        
        # Handle XML files
        elif filename.endswith('.xml'):
            return content
        
        return None
    
    def fetch_reports(self, db_manager):
        """Fetch and process DMARC reports"""
        mail = self.connect()
        processed_count = 0
        
        try:
            # Build search criteria based on days_limit
            if self.days_limit:
                since_date = datetime.now() - timedelta(days=self.days_limit)
                date_str = since_date.strftime('%d-%b-%Y')
                search_criteria = f'(SINCE {date_str})'
                logger.info(f"Searching emails since {date_str} (last {self.days_limit} days)")
            else:
                search_criteria = 'ALL'
                logger.info("Searching all emails")
            
            status, messages = mail.search(None, search_criteria)
            email_ids = messages[0].split()
            
            if self.days_limit:
                logger.info(f"Found {len(email_ids)} emails from the last {self.days_limit} days (since {date_str})")
            else:
                logger.info(f"Found {len(email_ids)} emails (all emails)")
            
            for email_id in email_ids:
                try:
                    # Fetch email
                    status, msg_data = mail.fetch(email_id, '(RFC822)')
                    
                    for response_part in msg_data:
                        if isinstance(response_part, tuple):
                            msg = email.message_from_bytes(response_part[1], policy=policy.default)
                            
                            # Get message ID
                            message_id = msg.get('Message-ID', f'unknown-{email_id}')
                            subject = msg.get('Subject', 'No Subject')
                            
                            # Check if already processed
                            if db_manager.is_email_processed(message_id):
                                logger.debug(f"Email {message_id} already processed")
                                continue
                            
                            logger.info(f"Processing email: {subject}")
                            
                            # Process attachments
                            for part in msg.walk():
                                if part.get_content_maintype() == 'multipart':
                                    continue
                                if part.get('Content-Disposition') is None:
                                    continue
                                
                                xml_content = self.extract_xml_from_attachment(part)
                                if xml_content:
                                    try:
                                        report_data = self.parser.parse_xml(xml_content)
                                        if db_manager.store_report(report_data):
                                            processed_count += 1
                                    except Exception as e:
                                        logger.error(f"Error processing attachment: {e}")
                            
                            # Mark email as processed
                            db_manager.mark_email_processed(message_id, subject)
                            
                except Exception as e:
                    logger.error(f"Error processing email {email_id}: {e}")
                    continue
            
            logger.info(f"Processed {processed_count} new reports")
            
        finally:
            mail.close()
            mail.logout()
        
        return processed_count


def main():
    """Main application loop"""
    # Get configuration from environment
    db_url = os.environ.get('DATABASE_URL')
    imap_server = os.environ.get('IMAP_SERVER')
    imap_port = int(os.environ.get('IMAP_PORT', 993))
    imap_user = os.environ.get('IMAP_USER')
    imap_password = os.environ.get('IMAP_PASSWORD')
    imap_folder = os.environ.get('IMAP_FOLDER', 'INBOX')
    fetch_interval = int(os.environ.get('FETCH_INTERVAL', 3600))
    fetch_days_limit = os.environ.get('FETCH_DAYS_LIMIT')
    
    # Convert days limit to integer if provided
    if fetch_days_limit:
        try:
            fetch_days_limit = int(fetch_days_limit)
            logger.info(f"Email fetch limited to last {fetch_days_limit} days")
        except ValueError:
            logger.warning(f"Invalid FETCH_DAYS_LIMIT value: {fetch_days_limit}, ignoring")
            fetch_days_limit = None
    
    if not all([db_url, imap_server, imap_user, imap_password]):
        logger.error("Missing required environment variables")
        return
    
    db_manager = DatabaseManager(db_url)
    fetcher = IMAPFetcher(imap_server, imap_port, imap_user, imap_password, imap_folder, fetch_days_limit)

    logger.info("DMARC IMAP Fetcher started")

    while True:
        try:
            logger.info("Starting fetch cycle")
            fetcher.fetch_reports(db_manager)
            logger.info(f"Waiting {fetch_interval} seconds until next fetch")
            time.sleep(fetch_interval)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            break
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
            time.sleep(60)  # Wait a minute before retrying


if __name__ == '__main__':
    main()
