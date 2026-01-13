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
    # Get filter parameters
    search = request.args.get('search', '').strip()
    domain_filter = request.args.get('domain', '').strip()
    org_filter = request.args.get('org', '').strip()
    date_from = request.args.get('date_from', '').strip()
    date_to = request.args.get('date_to', '').strip()
    page = int(request.args.get('page', 1))
    per_page = 20
    offset = (page - 1) * per_page
    
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
            
            # Get recent reports with filters
            where_clauses = []
            params = []
            
            if search:
                where_clauses.append("(r.org_name ILIKE %s OR r.domain ILIKE %s OR r.report_id ILIKE %s)")
                search_param = f"%{search}%"
                params.extend([search_param, search_param, search_param])
            
            if domain_filter:
                where_clauses.append("r.domain ILIKE %s")
                params.append(f"%{domain_filter}%")
            
            if org_filter:
                where_clauses.append("r.org_name ILIKE %s")
                params.append(f"%{org_filter}%")
            
            if date_from:
                where_clauses.append("r.date_range_begin >= %s")
                params.append(date_from)
            
            if date_to:
                where_clauses.append("r.date_range_end <= %s")
                params.append(date_to)
            
            where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
            
            # Count total filtered reports
            cur.execute(f"""
                SELECT COUNT(DISTINCT r.id)
                FROM reports r
                {where_sql}
            """, params)
            total_filtered = cur.fetchone()['count']
            total_pages = (total_filtered + per_page - 1) // per_page
            
            # Get filtered reports
            cur.execute(f"""
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
                {where_sql}
                GROUP BY r.id
                ORDER BY r.date_range_end DESC
                LIMIT %s OFFSET %s
            """, params + [per_page, offset])
            recent_reports = cur.fetchall()
            
            # Get list of unique domains for filter dropdown
            cur.execute("""
                SELECT DISTINCT domain FROM reports ORDER BY domain
            """)
            all_domains = [row['domain'] for row in cur.fetchall()]
            
            # Get list of unique organizations for filter dropdown
            cur.execute("""
                SELECT DISTINCT org_name FROM reports WHERE org_name IS NOT NULL ORDER BY org_name
            """)
            all_orgs = [row['org_name'] for row in cur.fetchall()]
            
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
                disposition_stats=disposition_stats,
                all_domains=all_domains,
                all_orgs=all_orgs,
                page=page,
                total_pages=total_pages,
                total_filtered=total_filtered,
                search=search,
                domain_filter=domain_filter,
                org_filter=org_filter,
                date_from=date_from,
                date_to=date_to
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


@app.route('/source-ip/<ip>')
@requires_auth
def source_ip_detail(ip):
    """Detailed analysis of a specific source IP"""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get IP summary - aggregate across all domains
            cur.execute("""
                SELECT 
                    r.source_ip,
                    string_agg(DISTINCT r.header_from, ', ') as domain,
                    SUM(r.count) as total_messages,
                    SUM(CASE WHEN r.dkim_result = 'pass' THEN r.count ELSE 0 END) as dkim_pass,
                    SUM(CASE WHEN r.spf_result = 'pass' THEN r.count ELSE 0 END) as spf_pass,
                    COUNT(DISTINCT rep.id) as report_count,
                    MAX(rep.date_range_end) as last_seen
                FROM records r
                JOIN reports rep ON r.report_id = rep.id
                WHERE r.source_ip = %s::inet
                GROUP BY r.source_ip
            """, (ip,))
            ip_summary = cur.fetchone()
            
            if not ip_summary:
                return "IP not found", 404
            
            # Get detailed records with report dates
            cur.execute("""
                SELECT 
                    r.id as report_id,
                    r.org_name,
                    r.report_id,
                    r.date_range_begin,
                    r.date_range_end,
                    rec.count,
                    rec.disposition,
                    rec.dkim_result,
                    rec.spf_result,
                    rec.header_from,
                    string_agg(DISTINCT da.domain || ' (' || da.result || ')', ', ') as dkim_details,
                    string_agg(DISTINCT sa.domain || ' (' || sa.result || ')', ', ') as spf_details
                FROM records rec
                JOIN reports r ON rec.report_id = r.id
                LEFT JOIN dkim_auth da ON rec.id = da.record_id
                LEFT JOIN spf_auth sa ON rec.id = sa.record_id
                WHERE rec.source_ip = %s::inet
                GROUP BY r.id, r.org_name, r.report_id, r.date_range_begin, r.date_range_end,
                         rec.id, rec.count, rec.disposition, rec.dkim_result, rec.spf_result, rec.header_from
                ORDER BY r.date_range_end DESC
            """, (ip,))
            records = cur.fetchall()
            
            # Get timeline data for this IP
            cur.execute("""
                SELECT 
                    DATE(r.date_range_end) as report_date,
                    SUM(rec.count) as total_messages,
                    SUM(CASE WHEN rec.dkim_result = 'pass' THEN rec.count ELSE 0 END) as dkim_pass,
                    SUM(CASE WHEN rec.spf_result = 'pass' THEN rec.count ELSE 0 END) as spf_pass,
                    SUM(CASE WHEN rec.disposition = 'none' THEN rec.count ELSE 0 END) as passed,
                    SUM(CASE WHEN rec.disposition IN ('quarantine', 'reject') THEN rec.count ELSE 0 END) as failed
                FROM records rec
                JOIN reports r ON rec.report_id = r.id
                WHERE rec.source_ip = %s::inet
                GROUP BY DATE(r.date_range_end)
                ORDER BY report_date DESC
                LIMIT 90
            """, (ip,))
            timeline = cur.fetchall()
            
            return render_template(
                'source_ip_detail.html',
                ip=ip,
                ip_summary=ip_summary,
                records=records,
                timeline=timeline
            )
    finally:
        conn.close()


@app.route('/insights')
@requires_auth
def insights():
    """Generate insights and recommendations"""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            insights = []
            
            # Check for domains with high failure rate
            cur.execute("""
                SELECT 
                    domain,
                    total_messages,
                    passed_messages,
                    quarantined_messages,
                    rejected_messages,
                    ROUND(((quarantined_messages + rejected_messages)::numeric / 
                           NULLIF(total_messages, 0) * 100), 2) as failure_rate
                FROM domain_stats
                WHERE total_messages > 100
                  AND ((quarantined_messages + rejected_messages)::numeric / 
                       NULLIF(total_messages, 0) * 100) > 10
                ORDER BY failure_rate DESC
            """)
            high_failure_domains = cur.fetchall()
            
            if high_failure_domains:
                insights.append({
                    'type': 'warning',
                    'title': 'High Failure Rate Detected',
                    'description': f'{len(high_failure_domains)} domain(s) have more than 10% failed authentication',
                    'data': high_failure_domains,
                    'recommendation': 'Review DKIM and SPF configurations for these domains. Check if authorized senders are properly configured.'
                })
            
            # Check for IPs with authentication failures
            cur.execute("""
                SELECT 
                    source_ip,
                    domain,
                    total_messages,
                    dkim_pass,
                    spf_pass,
                    ROUND((dkim_pass::numeric / NULLIF(total_messages, 0) * 100), 2) as dkim_pass_rate,
                    ROUND((spf_pass::numeric / NULLIF(total_messages, 0) * 100), 2) as spf_pass_rate
                FROM source_ip_stats
                WHERE total_messages > 50
                  AND (dkim_pass::numeric / NULLIF(total_messages, 0) * 100) < 50
                ORDER BY total_messages DESC
                LIMIT 10
            """)
            problematic_ips = cur.fetchall()
            
            if problematic_ips:
                insights.append({
                    'type': 'danger',
                    'title': 'Problematic Source IPs',
                    'description': f'{len(problematic_ips)} IP(s) have low DKIM pass rates',
                    'data': problematic_ips,
                    'recommendation': 'These IPs may be unauthorized senders or misconfigured. Consider blocking or investigating.'
                })
            
            # Check policy compliance
            cur.execute("""
                SELECT 
                    domain,
                    p as policy,
                    COUNT(*) as report_count,
                    MAX(date_range_end) as last_report
                FROM reports
                WHERE p != 'reject'
                GROUP BY domain, p
                ORDER BY report_count DESC
            """)
            weak_policies = cur.fetchall()
            
            if weak_policies:
                insights.append({
                    'type': 'info',
                    'title': 'Policy Recommendations',
                    'description': f'{len(weak_policies)} domain(s) not using "reject" policy',
                    'data': weak_policies,
                    'recommendation': 'Consider upgrading to p=reject after monitoring shows good authentication rates (>95% pass).'
                })
            
            # Recent activity
            cur.execute("""
                SELECT 
                    COUNT(*) as new_reports,
                    SUM(CASE WHEN date_range_end > NOW() - INTERVAL '7 days' THEN 1 ELSE 0 END) as this_week
                FROM reports
            """)
            activity = cur.fetchone()
            
            if activity and activity['this_week'] == 0:
                insights.append({
                    'type': 'warning',
                    'title': 'No Recent Reports',
                    'description': 'No DMARC reports received in the last 7 days',
                    'data': [],
                    'recommendation': 'Check if IMAP fetcher is running and email forwarding is configured correctly.'
                })
            
            return render_template('insights.html', insights=insights)
    finally:
        conn.close()


@app.route('/guide')
@requires_auth
def dmarc_guide():
    """DMARC understanding guide"""
    return render_template('dmarc_guide.html')


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


@app.route('/api/timeline')
@requires_auth
def api_timeline():
    """API endpoint for timeline chart data"""
    days = int(request.args.get('days', 30))
    ip = request.args.get('ip', None)
    
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if ip:
                # Timeline for specific IP
                cur.execute("""
                    SELECT 
                        DATE(r.date_range_end) as report_date,
                        SUM(rec.count) as total_messages,
                        SUM(CASE WHEN rec.disposition = 'none' THEN rec.count ELSE 0 END) as passed,
                        SUM(CASE WHEN rec.disposition = 'quarantine' THEN rec.count ELSE 0 END) as quarantined,
                        SUM(CASE WHEN rec.disposition = 'reject' THEN rec.count ELSE 0 END) as rejected,
                        SUM(CASE WHEN rec.dkim_result = 'pass' THEN rec.count ELSE 0 END) as dkim_pass,
                        SUM(CASE WHEN rec.spf_result = 'pass' THEN rec.count ELSE 0 END) as spf_pass
                    FROM reports r
                    JOIN records rec ON r.id = rec.report_id
                    WHERE rec.source_ip = %s::inet
                      AND r.date_range_end >= NOW() - INTERVAL '%s days'
                    GROUP BY DATE(r.date_range_end)
                    ORDER BY report_date ASC
                """, (ip, days))
            else:
                # Overall timeline
                cur.execute("""
                    SELECT 
                        DATE(r.date_range_end) as report_date,
                        SUM(rec.count) as total_messages,
                        SUM(CASE WHEN rec.disposition = 'none' THEN rec.count ELSE 0 END) as passed,
                        SUM(CASE WHEN rec.disposition = 'quarantine' THEN rec.count ELSE 0 END) as quarantined,
                        SUM(CASE WHEN rec.disposition = 'reject' THEN rec.count ELSE 0 END) as rejected,
                        SUM(CASE WHEN rec.dkim_result = 'pass' THEN rec.count ELSE 0 END) as dkim_pass,
                        SUM(CASE WHEN rec.spf_result = 'pass' THEN rec.count ELSE 0 END) as spf_pass
                    FROM reports r
                    JOIN records rec ON r.id = rec.report_id
                    WHERE r.date_range_end >= NOW() - INTERVAL '%s days'
                    GROUP BY DATE(r.date_range_end)
                    ORDER BY report_date ASC
                """, (days,))
            timeline = cur.fetchall()
            return jsonify(timeline)
    finally:
        conn.close()


@app.route('/export/reports')
@requires_auth
def export_reports():
    """Export reports to CSV"""
    import csv
    from io import StringIO
    
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    r.id,
                    r.org_name,
                    r.domain,
                    r.report_id,
                    r.date_range_begin,
                    r.date_range_end,
                    r.p as policy,
                    COUNT(rec.id) as record_count,
                    SUM(rec.count) as message_count,
                    SUM(CASE WHEN rec.disposition = 'none' THEN rec.count ELSE 0 END) as passed,
                    SUM(CASE WHEN rec.disposition = 'quarantine' THEN rec.count ELSE 0 END) as quarantined,
                    SUM(CASE WHEN rec.disposition = 'reject' THEN rec.count ELSE 0 END) as rejected
                FROM reports r
                LEFT JOIN records rec ON r.id = rec.report_id
                GROUP BY r.id
                ORDER BY r.date_range_end DESC
            """)
            reports = cur.fetchall()
            
            output = StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                'ID', 'Organization', 'Domain', 'Report ID', 'Date Begin', 'Date End',
                'Policy', 'Record Count', 'Message Count', 'Passed', 'Quarantined', 'Rejected'
            ])
            
            # Write data
            for report in reports:
                writer.writerow([
                    report['id'],
                    report['org_name'],
                    report['domain'],
                    report['report_id'],
                    report['date_range_begin'],
                    report['date_range_end'],
                    report['policy'],
                    report['record_count'] or 0,
                    report['message_count'] or 0,
                    report['passed'] or 0,
                    report['quarantined'] or 0,
                    report['rejected'] or 0
                ])
            
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={"Content-Disposition": "attachment;filename=dmarc_reports.csv"}
            )
    finally:
        conn.close()


@app.route('/export/records/<int:report_id>')
@requires_auth
def export_report_records(report_id):
    """Export specific report records to CSV"""
    import csv
    from io import StringIO
    
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    r.*,
                    string_agg(DISTINCT da.domain || ' (' || da.result || ')', ', ') as dkim_details,
                    string_agg(DISTINCT sa.domain || ' (' || sa.result || ')', ', ') as spf_details
                FROM records r
                LEFT JOIN dkim_auth da ON r.id = da.record_id
                LEFT JOIN spf_auth sa ON r.id = sa.record_id
                WHERE r.report_id = %s
                GROUP BY r.id
                ORDER BY r.count DESC
            """, (report_id,))
            records = cur.fetchall()
            
            output = StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                'Source IP', 'Count', 'Disposition', 'DKIM Result', 'SPF Result',
                'Header From', 'DKIM Details', 'SPF Details'
            ])
            
            # Write data
            for record in records:
                writer.writerow([
                    record['source_ip'],
                    record['count'],
                    record['disposition'],
                    record['dkim_result'],
                    record['spf_result'],
                    record['header_from'],
                    record['dkim_details'] or '',
                    record['spf_details'] or ''
                ])
            
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={"Content-Disposition": f"attachment;filename=report_{report_id}_records.csv"}
            )
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
    # This is only used for development
    # Production uses gunicorn (see Dockerfile)
    import os
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
