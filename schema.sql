-- DMARC Reports Schema

-- Table to store metadata about each DMARC report
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    org_name VARCHAR(255),
    email VARCHAR(255),
    extra_contact_info TEXT,
    report_id VARCHAR(255) UNIQUE NOT NULL,
    date_range_begin TIMESTAMP,
    date_range_end TIMESTAMP,
    domain VARCHAR(255),
    adkim VARCHAR(10),
    aspf VARCHAR(10),
    p VARCHAR(10),
    sp VARCHAR(10),
    pct INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    raw_xml TEXT
);

-- Table to store individual record entries from DMARC reports
CREATE TABLE IF NOT EXISTS records (
    id SERIAL PRIMARY KEY,
    report_id INTEGER REFERENCES reports(id) ON DELETE CASCADE,
    source_ip INET,
    count INTEGER,
    disposition VARCHAR(20),
    dkim_result VARCHAR(20),
    spf_result VARCHAR(20),
    header_from VARCHAR(255),
    envelope_from VARCHAR(255),
    envelope_to VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table for DKIM authentication results
CREATE TABLE IF NOT EXISTS dkim_auth (
    id SERIAL PRIMARY KEY,
    record_id INTEGER REFERENCES records(id) ON DELETE CASCADE,
    domain VARCHAR(255),
    selector VARCHAR(255),
    result VARCHAR(20),
    human_result TEXT
);

-- Table for SPF authentication results
CREATE TABLE IF NOT EXISTS spf_auth (
    id SERIAL PRIMARY KEY,
    record_id INTEGER REFERENCES records(id) ON DELETE CASCADE,
    domain VARCHAR(255),
    scope VARCHAR(50),
    result VARCHAR(20)
);

-- Table to track processed email attachments (to avoid duplicates)
CREATE TABLE IF NOT EXISTS processed_emails (
    id SERIAL PRIMARY KEY,
    message_id VARCHAR(255) UNIQUE,
    subject VARCHAR(500),
    processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(50) -- 'imap' or 'manual'
);

-- Indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_reports_report_id ON reports(report_id);
CREATE INDEX IF NOT EXISTS idx_reports_domain ON reports(domain);
CREATE INDEX IF NOT EXISTS idx_reports_date_range ON reports(date_range_begin, date_range_end);
CREATE INDEX IF NOT EXISTS idx_records_report_id ON records(report_id);
CREATE INDEX IF NOT EXISTS idx_records_source_ip ON records(source_ip);
CREATE INDEX IF NOT EXISTS idx_records_disposition ON records(disposition);
CREATE INDEX IF NOT EXISTS idx_processed_emails_message_id ON processed_emails(message_id);

-- View for aggregated statistics by domain
CREATE OR REPLACE VIEW domain_stats AS
SELECT 
    rep.domain,
    COUNT(DISTINCT rep.id) as total_reports,
    SUM(r.count) as total_messages,
    SUM(CASE WHEN r.disposition = 'none' THEN r.count ELSE 0 END) as passed_messages,
    SUM(CASE WHEN r.disposition = 'quarantine' THEN r.count ELSE 0 END) as quarantined_messages,
    SUM(CASE WHEN r.disposition = 'reject' THEN r.count ELSE 0 END) as rejected_messages,
    MIN(rep.date_range_begin) as first_report_date,
    MAX(rep.date_range_end) as last_report_date
FROM reports rep
JOIN records r ON rep.id = r.report_id
GROUP BY rep.domain;

-- View for source IP analysis
CREATE OR REPLACE VIEW source_ip_stats AS
SELECT 
    r.source_ip,
    r.header_from as domain,
    SUM(r.count) as total_messages,
    SUM(CASE WHEN r.dkim_result = 'pass' THEN r.count ELSE 0 END) as dkim_pass,
    SUM(CASE WHEN r.spf_result = 'pass' THEN r.count ELSE 0 END) as spf_pass,
    COUNT(DISTINCT rep.id) as report_count,
    MAX(rep.date_range_end) as last_seen
FROM records r
JOIN reports rep ON r.report_id = rep.id
GROUP BY r.source_ip, r.header_from;
