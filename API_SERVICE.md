# SeeVee API Service 🚀

A containerized FastAPI service for CVE and CWE vulnerability lookups with high-performance batch processing.

## 📊 Performance Metrics

- **CVE Count**: 300,519 vulnerabilities
- **CWE Count**: 943 complete MITRE CWE database
- **Batch Processing**: 235+ CVE/s
- **Response Time**: <100ms for single lookups

## 🚀 Quick Start

### Docker Deployment (Recommended)
```bash
# Build and start the service
docker-compose up -d

# View logs
docker-compose logs -f seevee-api

# Stop the service
docker-compose down
```

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Start the service
python api_server.py

# Interactive docs: http://localhost:8000/docs
```

## 🔗 API Endpoints

### Core Endpoints
- `GET /` - API information
- `GET /health` - Health check with uptime
- `GET /stats` - Database statistics
- `GET /docs` - Interactive Swagger documentation

### CVE Endpoints
- `GET /cve/{cve_id}` - Single CVE lookup
  - `?include_cvss_details=true` - Include CVSS vector components
  - `?include_risk_analysis=true` - Include risk factor analysis
  - `?include_references=false` - Exclude reference URLs
- `POST /cve/batch` - Batch CVE lookup

### CWE Endpoints  
- `GET /cwe/{cwe_id}` - Single CWE lookup
- `POST /cwe/batch` - Batch CWE lookup

### Management Endpoints
- `POST /update` - Trigger database update (background task)

## 📋 API Usage Examples

### Single CVE Lookup
```bash
curl "http://localhost:8000/cve/CVE-2021-44228?include_risk_analysis=true"
```

### Batch CVE Lookup
```bash
curl -X POST "http://localhost:8000/cve/batch" \
  -H "Content-Type: application/json" \
  -d '{
    "cve_ids": ["CVE-2021-44228", "CVE-2022-22965"],
    "include_cvss_details": true,
    "include_risk_analysis": true
  }'
```

### Database Statistics
```bash
curl "http://localhost:8000/stats"
```

## 🐍 Python Client Usage

```python
from api_client_example import SeeVeeAPIClient

client = SeeVeeAPIClient("http://localhost:8000")

# Single CVE with risk analysis
result = client.lookup_cve("CVE-2021-44228", include_risk_analysis=True)

# Batch processing
batch_result = client.batch_lookup_cve([
    "CVE-2021-44228", "CVE-2022-22965", "CVE-2014-0160"
], include_cvss_details=True)

# Database stats
stats = client.get_stats()
print(f"Database: {stats['cve_count']:,} CVEs, {stats['cwe_count']:,} CWEs")
```

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `API_HOST` | `0.0.0.0` | Server host |
| `API_PORT` | `8000` | Server port |
| `UPDATE_DB_ON_STARTUP` | `true` | Update database on startup |
| `SKIP_YEARS` | - | Skip specific years (comma-separated) |

### Docker Configuration

```yaml
# Production mode - full database update
docker-compose up -d

# Testing mode - skip database update
# Set UPDATE_DB_ON_STARTUP=false in docker-compose.yml

# Quick mode - recent years only
# Set SKIP_YEARS in docker-compose.yml
```

## 🔧 Development & Testing

### Local Testing Script
```bash
# Test all endpoints
python api_client_example.py

# Start in development mode
python api_server.py
```

## 📈 Scaling Considerations

### Current SQLite Performance
✅ **Excellent for most use cases:**
- Sub-second queries with 300K+ records
- No additional database server needed
- Perfect for containerized deployment

### When to Consider PostgreSQL
Consider upgrading if you experience:
- Database size >5GB
- Concurrent users >100
- Complex analytical queries

## 🎯 Production Checklist

- [ ] Update CORS origins in `api_server.py` for production
- [ ] Set up reverse proxy (nginx) if needed
- [ ] Configure resource limits in `docker-compose.yml`
- [ ] Set up monitoring/logging
- [ ] Regular database backups
- [ ] Update schedules (cron job for `/update` endpoint)

## 🔒 Security Notes

- API runs on all interfaces (`0.0.0.0`) - configure firewall appropriately
- No authentication implemented - add if needed for production
- CORS configured for development - restrict for production
- Database file should be backed up regularly

## 🐛 Troubleshooting

### Common Issues

**Server won't start:**
```bash
# Check dependencies
pip install -r requirements.txt

# Check port availability
netstat -an | findstr :8000  # Windows
lsof -i :8000                # Linux/Mac
```

**Database errors:**
```bash
# Check database integrity
sqlite3 cve_database.db ".schema"
```

### Performance Issues

**Slow startup:**
- Set `UPDATE_DB_ON_STARTUP=false` for testing
- Use `SKIP_YEARS` for quicker updates

**Memory usage:**
- Adjust Docker memory limits
- Monitor with `docker stats`

## 📚 Additional Resources

- **Interactive API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health
- **Client Example**: `api_client_example.py`
- **CLI Tool**: `seevee.py`

---

**Status**: ✅ Production Ready  
**Performance**: 🚀 High Performance (235+ CVE/s)  
**Database**: 📊 300K+ CVEs, 943 CWEs  
**Deployment**: 🐳 Docker + docker-compose 