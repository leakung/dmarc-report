# DMARC Report Analyzer (DMRP)

A comprehensive DMARC report analyzer system that fetches reports from IMAP, stores them in PostgreSQL, and provides detailed analysis through a web dashboard.

## Features

- **Automated IMAP Fetching**: Periodically fetches DMARC reports from an IMAP mailbox
- **Manual Import**: Import DMARC reports from local ZIP/GZ/XML files for testing
- **PostgreSQL Storage**: Stores parsed DMARC data in a relational database
- **Web Dashboard**: 
  - Overview statistics and metrics
  - Domain-specific analysis
  - Source IP tracking
  - Authentication results (DKIM, SPF)
  - Detailed report views with raw XML
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

The web application also provides JSON API endpoints:

- `GET /api/stats` - Overall statistics
- `GET /api/domains` - List of all domains with statistics

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
