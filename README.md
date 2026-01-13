# DMARC Report Analyzer (DMRP)

A comprehensive DMARC report analyzer system that fetches reports from IMAP, stores them in PostgreSQL, and provides detailed analysis through a web dashboard.

## Features

- **Automated IMAP Fetching**: Periodically fetches DMARC reports from an IMAP mailbox
- **Manual Import**: Import DMARC reports from local ZIP/GZ/XML files for testing
- **PostgreSQL Storage**: Stores parsed DMARC data in a relational database
- **Advanced Web Dashboard**: 
  - **Interactive Charts**: Visual analytics with Chart.js (disposition breakdown, timeline trends, authentication results)
  - **Search & Filter**: Multi-criteria filtering by domain, organization, date range, IP, and authentication status
  - **Pagination**: Easy navigation through large report datasets
  - **Detailed Analysis**: Deep dive into individual reports with filterable record tables
  - **Source IP Deep Dive**: Click any IP to see complete history with dates and reports
  - **Export Capabilities**: CSV export for reports and individual record details
  - **Real-time Statistics**: Overall metrics, domain-specific analysis, source IP tracking
  - **Authentication Tracking**: DKIM and SPF validation results with detailed breakdowns
  - **Automated Insights**: Smart recommendations for security issues and misconfigurations
  - **DMARC Guide**: Built-in comprehensive guide to understand and interpret reports
  - **Raw XML Access**: View original report XML for debugging
- **Docker-based**: Easy deployment with Docker Compose

## System Architecture

The system consists of three main components:

1. **PostgreSQL Database**: Stores all DMARC report data
2. **IMAP Fetcher Service**: Continuously monitors IMAP mailbox for new reports
3. **Web Dashboard**: Flask-based web application for viewing and analyzing reports

## Quick Start

### 1. Setup Environment

Copy the example environment file and configure it:

```bash
cp .env.example .env
nano .env
```

Configure the following variables in `.env`:

```ini
# Database
POSTGRES_PASSWORD=your_secure_password

# IMAP Settings
IMAP_SERVER=imap.example.com
IMAP_USER=dmarc@example.com
IMAP_PASSWORD=your_imap_password
IMAP_FOLDER=INBOX
FETCH_INTERVAL=3600  # Fetch every hour
```

### 2. Start the Services

```bash
docker-compose up -d
```

This will start:
- PostgreSQL database on port 5432
- Web dashboard on port 8080
- IMAP fetcher service

### 3. Access the Dashboard

Open your browser and navigate to:
```
http://localhost:8080
```

### Using Docker to run manual import:

```bash
# Copy your test files to the uploads directory
cp /path/to/test-reports/* uploads/

# Run import inside the web container (which has access to uploads)
docker-compose exec web python /app/../manual_import.py /uploads/
```

## Database Schema

The system uses the following main tables:

- **reports**: DMARC report metadata (organization, domain, policy, date range)
- **records**: Individual record entries from reports (source IP, counts, disposition)
- **dkim_auth**: DKIM authentication results
- **spf_auth**: SPF authentication results
- **processed_emails**: Tracking of processed emails to avoid duplicates

Views:
- **domain_stats**: Aggregated statistics by domain
- **source_ip_stats**: Analysis of source IP addresses

## API Endpoints

The web application provides JSON API endpoints and export functionality:

### JSON APIs
- `GET /api/stats` - Overall statistics
- `GET /api/domains` - List of all domains with statistics
- `GET /api/timeline?days=30` - Timeline chart data (message trends over time)

### Export Endpoints
- `GET /export/reports` - Export all reports to CSV
- `GET /export/records/<report_id>` - Export specific report records to CSV

### Web Interface Features

#### Dashboard (/)
- **Overview Statistics**: Total reports, domains, messages, and unique source IPs
- **Interactive Charts**: 
  - Pie chart for message disposition distribution
  - Line chart showing 30-day trend
- **Search & Filter**: 
  - Keyword search across report ID, organization, and domain
  - Filter by specific domain or organization
  - Date range filtering
- **Pagination**: Navigate through large datasets (20 reports per page)
- **Quick Actions**: Export all reports to CSV

#### Report Detail (/report/<id>)
- **Comprehensive Metadata**: Organization, domain, policy configuration
- **Visual Analytics**: Charts for disposition and authentication results
- **Filterable Records Table**: 
  - Filter by source IP, disposition, DKIM result, or SPF result
  - Real-time client-side filtering
  - Detailed authentication information
- **Export**: Download report records as CSV
- **Raw XML**: Access to original report data

#### Source IP Analysis (/source-ips)
- **Overview of All Source IPs**: Top 100 IPs by message volume
- **Filter Capabilities**:
  - Filter by IP address
  - Filter by domain
  - Filter by authentication health (Good/Warning/Poor)
- **Health Indicators**: Color-coded authentication pass rates
- **Click to Deep Dive**: View complete IP history

#### Source IP Detail (/source-ip/<ip>)
- **Complete IP History**: See all dates this IP appeared in reports
- **Timeline Chart**: Visual representation of activity over 90 days
- **Daily Breakdown**: Day-by-day authentication results
- **Report Links**: Click to view the full report for any date
- **Health Analysis**: Automatic recommendations based on authentication rates
- **Authentication Tracking**: DKIM/SPF pass rates by date

#### Insights & Recommendations (/insights)
- **Automated Analysis**: System automatically identifies issues
- **Severity-based Categorization**: Critical, Warning, Info levels
- **Specific Recommendations**: Actionable steps for each issue
- **Issue Detection**:
  - High failure rate domains
  - Problematic source IPs
  - Weak DMARC policies
  - Missing reports

#### DMARC Guide (/guide)
- **Comprehensive Documentation**: Understand DMARC, DKIM, SPF
- **Common Scenarios**: Real-world examples with solutions
- **Quick Reference**: Key metrics and what to look for
- **Step-by-Step Workflows**: Weekly monitoring checklist
- **Color-coded Examples**: Easy-to-understand explanations

#### Domain Analysis (/domain/<domain>)
- Domain-specific statistics and trends
- Source IP analysis for the domain
- Historical report timeline

Example:
```bash
curl http://localhost:8080/api/stats
curl http://localhost:8080/api/domains
```

## Monitoring and Logs

View logs for each service:

```bash
# All services
docker-compose logs -f

# IMAP fetcher only
docker-compose logs -f fetcher

# Web dashboard only
docker-compose logs -f web

# Database
docker-compose logs -f postgres
```

## Configuration Options

### IMAP Fetcher

- `IMAP_SERVER`: IMAP server hostname
- `IMAP_PORT`: IMAP port (default: 993 for SSL)
- `IMAP_USER`: IMAP username
- `IMAP_PASSWORD`: IMAP password
- `IMAP_FOLDER`: Mailbox folder to monitor (default: INBOX)
- `FETCH_INTERVAL`: Seconds between fetch cycles (default: 3600)

### Web Dashboard

- `WEB_PORT`: Port for web interface (default: 8080)
- `DATABASE_URL`: PostgreSQL connection URL (auto-configured)

### Database

- `POSTGRES_DB`: Database name (default: dmrp)
- `POSTGRES_USER`: Database user (default: dmrp)
- `POSTGRES_PASSWORD`: Database password (CHANGE THIS!)
- `POSTGRES_PORT`: Database port (default: 5432)

## Troubleshooting

### IMAP Fetcher not connecting

1. Check IMAP credentials in `.env`
2. Verify IMAP server allows connections from your IP
3. Check logs: `docker-compose logs imap_fetcher`
4. For Gmail, you may need an "App Password"

### No reports showing in dashboard

1. Check if IMAP fetcher is running: `docker-compose ps`
2. Check if there are emails in the IMAP folder
3. Try manual import to test the system
4. Check database: `docker-compose exec postgres psql -U dmrp -d dmrp -c "SELECT COUNT(*) FROM reports;"`

### Web dashboard not accessible

1. Check if service is running: `docker-compose ps`
2. Verify port 8080 is not in use: `sudo netstat -tlnp | grep 8080`
3. Check logs: `docker-compose logs web`

## Data Management

### Backup Database

```bash
docker-compose exec postgres pg_dump -U dmrp dmrp > backup_$(date +%Y%m%d).sql
```

### Restore Database

```bash
docker-compose exec -T postgres psql -U dmrp dmrp < backup.sql
```

### Clear All Data

```bash
docker-compose exec postgres psql -U dmrp -d dmrp -c "TRUNCATE reports, records, dkim_auth, spf_auth, processed_emails CASCADE;"
```

## Development

### Directory Structure

```
dmrp/
├── docker-compose.yml       # Docker services configuration
├── schema.sql              # Database schema
├── .env.example            # Example environment variables
├── Dockerfile.web          # Web application Dockerfile
├── Dockerfile.fetcher      # IMAP fetcher Dockerfile
├── requirements-web.txt    # Python deps for web
├── requirements-fetcher.txt # Python deps for fetcher
├── manual_import.py        # Manual import script
├── fetcher/
│   └── imap_fetcher.py    # IMAP fetcher service
├── web/
│   ├── app.py             # Flask application
│   └── templates/         # HTML templates
└── uploads/               # Directory for manual test files
```

### Extending the System

To add new features:

1. **Database**: Modify `schema.sql` and rebuild database
2. **Fetcher**: Edit `fetcher/imap_fetcher.py`
3. **Web**: Edit `web/app.py` and templates

## Security Considerations

1. **Change default passwords** in `.env` file
2. **Use strong passwords** for database and IMAP
3. **Restrict database port** (5432) to localhost if not needed externally
4. **Use HTTPS** for production deployments (add reverse proxy)
5. **Regular backups** of the database
6. **Keep Docker images updated**: `docker-compose pull`

## License

This project is provided as-is for DMARC report analysis purposes.

## Support

For issues or questions:
1. Check the logs: `docker-compose logs`
2. Verify configuration in `.env`
3. Test with manual import first
4. Check database connectivity

## Useful Queries

Connect to database:
```bash
docker-compose exec postgres psql -U dmrp dmrp
```

Useful SQL queries:
```sql
-- Count reports by organization
SELECT org_name, COUNT(*) FROM reports GROUP BY org_name;

-- Find failed authentications
SELECT source_ip, COUNT(*) 
FROM records 
WHERE disposition != 'none' 
GROUP BY source_ip 
ORDER BY COUNT(*) DESC;

-- Recent activity
SELECT domain, date_range_end, COUNT(*) 
FROM reports 
GROUP BY domain, date_range_end 
ORDER BY date_range_end DESC 
LIMIT 10;
```
