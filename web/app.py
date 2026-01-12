#!/usr/bin/env python3
"""
DMARC Analyzer Web Dashboard
"""

from flask import Flask, render_template, request, jsonify, Response
from functools import wraps
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.environ.get('DATABASE_URL')

# Basic Auth configuration
BASIC_AUTH_USERNAME = os.environ.get('BASIC_AUTH_USERNAME', 'admin')
BASIC_AUTH_PASSWORD = os.environ.get('BASIC_AUTH_PASSWORD', 'changeme123')


def check_auth(username, password):
    """Check if a username/password combination is valid."""
    return username == BASIC_AUTH_USERNAME and password == BASIC_AUTH_PASSWORD


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Access denied. Please provide valid credentials.',
        401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )


def requires_auth(f):
    """Decorator to require HTTP basic auth"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


def get_db_connection():
    """Get database connection"""
    return psycopg2.connect(DATABASE_URL)


@app.route('/')
@requires_auth
def index():
    """Dashboard home page"""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get overall statistics
            cur.execute("""
                SELECT 
                    COUNT(DISTINCT r.id) as total_reports,
                    COUNT(DISTINCT r.domain) as total_domains,
                    COUNT(DISTINCT rec.source_ip) as total_source_ips,
                    SUM(rec.count) as total_messages,
                    MIN(r.date_range_begin) as first_report_date,
                    MAX(r.date_range_end) as last_report_date
                FROM reports r
                LEFT JOIN records rec ON r.id = rec.report_id
            """)
            overall_stats = cur.fetchone()
            
            # Get domain statistics
            cur.execute("""
                SELECT * FROM domain_stats
                ORDER BY total_messages DESC
                LIMIT 10
            """)
            domain_stats = cur.fetchall()
            
            # Get recent reports
            cur.execute("""
                SELECT 
                    r.id,
                    r.org_name,
                    r.domain,
                    r.date_range_begin,
                    r.date_range_end,
                    COUNT(rec.id) as record_count,
                    SUM(rec.count) as message_count
                FROM reports r
                LEFT JOIN records rec ON r.id = rec.report_id
                GROUP BY r.id
                ORDER BY r.date_range_end DESC
                LIMIT 20
            """)
            recent_reports = cur.fetchall()
            
            # Get disposition breakdown
            cur.execute("""
                SELECT 
                    disposition,
                    SUM(count) as total
                FROM records
                GROUP BY disposition
            """)
            disposition_stats = cur.fetchall()
            
            return render_template(
                'index.html',
                overall_stats=overall_stats,
                domain_stats=domain_stats,
                recent_reports=recent_reports,
                disposition_stats=disposition_stats
            )
    finally:
        conn.close()


@app.route('/report/<int:report_id>')
@requires_auth
def report_detail(report_id):
    """Detailed view of a single report"""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get report metadata
            cur.execute("""
                SELECT * FROM reports WHERE id = %s
            """, (report_id,))
            report = cur.fetchone()
            
            if not report:
                return "Report not found", 404
            
            # Get records
            cur.execute("""
                SELECT 
                    r.*,
                    ARRAY_AGG(DISTINCT da.domain || ' (' || da.result || ')') 
                        FILTER (WHERE da.id IS NOT NULL) as dkim_details,
                    ARRAY_AGG(DISTINCT sa.domain || ' (' || sa.result || ')') 
                        FILTER (WHERE sa.id IS NOT NULL) as spf_details
                FROM records r
                LEFT JOIN dkim_auth da ON r.id = da.record_id
                LEFT JOIN spf_auth sa ON r.id = sa.record_id
                WHERE r.report_id = %s
                GROUP BY r.id
                ORDER BY r.count DESC
            """, (report_id,))
            records = cur.fetchall()
            
            # Get summary statistics
            cur.execute("""
                SELECT 
                    SUM(count) as total_messages,
                    COUNT(*) as unique_sources,
                    SUM(CASE WHEN disposition = 'none' THEN count ELSE 0 END) as passed,
                    SUM(CASE WHEN disposition = 'quarantine' THEN count ELSE 0 END) as quarantined,
                    SUM(CASE WHEN disposition = 'reject' THEN count ELSE 0 END) as rejected,
                    SUM(CASE WHEN dkim_result = 'pass' THEN count ELSE 0 END) as dkim_pass,
                    SUM(CASE WHEN spf_result = 'pass' THEN count ELSE 0 END) as spf_pass
                FROM records
                WHERE report_id = %s
            """, (report_id,))
            summary = cur.fetchone()
            
            return render_template(
                'report_detail.html',
                report=report,
                records=records,
                summary=summary
            )
    finally:
        conn.close()


@app.route('/domain/<domain>')
@requires_auth
def domain_detail(domain):
    """Detailed analysis of a specific domain"""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get domain summary
            cur.execute("""
                SELECT * FROM domain_stats WHERE domain = %s
            """, (domain,))
            domain_summary = cur.fetchone()
            
            if not domain_summary:
                return "Domain not found", 404
            
            # Get source IP analysis for this domain
            cur.execute("""
                SELECT * FROM source_ip_stats 
                WHERE domain = %s
                ORDER BY total_messages DESC
            """, (domain,))
            source_ips = cur.fetchall()
            
            # Get reports for this domain
            cur.execute("""
                SELECT 
                    r.id,
                    r.org_name,
                    r.date_range_begin,
                    r.date_range_end,
                    COUNT(rec.id) as record_count,
                    SUM(rec.count) as message_count
                FROM reports r
                JOIN records rec ON r.id = rec.report_id
                WHERE rec.header_from = %s
                GROUP BY r.id
                ORDER BY r.date_range_end DESC
            """, (domain,))
            reports = cur.fetchall()
            
            # Get authentication results over time
            cur.execute("""
                SELECT 
                    DATE(r.date_range_end) as report_date,
                    SUM(rec.count) as total_messages,
                    SUM(CASE WHEN rec.dkim_result = 'pass' THEN rec.count ELSE 0 END) as dkim_pass,
                    SUM(CASE WHEN rec.spf_result = 'pass' THEN rec.count ELSE 0 END) as spf_pass,
                    SUM(CASE WHEN rec.disposition = 'none' THEN rec.count ELSE 0 END) as passed,
                    SUM(CASE WHEN rec.disposition IN ('quarantine', 'reject') THEN rec.count ELSE 0 END) as failed
                FROM reports r
                JOIN records rec ON r.id = rec.report_id
                WHERE rec.header_from = %s
                GROUP BY DATE(r.date_range_end)
                ORDER BY report_date DESC
                LIMIT 30
            """, (domain,))
            timeline = cur.fetchall()
            
            return render_template(
                'domain_detail.html',
                domain=domain,
                domain_summary=domain_summary,
                source_ips=source_ips,
                reports=reports,
                timeline=timeline
            )
    finally:
        conn.close()


@app.route('/source-ips')
@requires_auth
def source_ips():
    """Analysis of source IPs"""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM source_ip_stats
                ORDER BY total_messages DESC
                LIMIT 100
            """)
            ips = cur.fetchall()
            
            return render_template('source_ips.html', ips=ips)
    finally:
        conn.close()


@app.route('/api/stats')
@requires_auth
def api_stats():
    """API endpoint for statistics"""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    COUNT(DISTINCT r.id) as total_reports,
                    COUNT(DISTINCT r.domain) as total_domains,
                    SUM(rec.count) as total_messages
                FROM reports r
                LEFT JOIN records rec ON r.id = rec.report_id
            """)
            stats = cur.fetchone()
            return jsonify(stats)
    finally:
        conn.close()


@app.route('/api/domains')
@requires_auth
def api_domains():
    """API endpoint for domain list"""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT * FROM domain_stats
                ORDER BY total_messages DESC
            """)
            domains = cur.fetchall()
            return jsonify(domains)
    finally:
        conn.close()


@app.template_filter('datetime')
def format_datetime(value):
    """Format datetime for templates"""
    if value is None:
        return ""
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.strftime('%Y-%m-%d %H:%M:%S')


@app.template_filter('percentage')
def format_percentage(value, total):
    """Calculate and format percentage"""
    if not total or total == 0:
        return "0%"
    return f"{(value / total * 100):.1f}%"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
