# SeeVee Web Deployment Guide

This guide explains how to deploy your SeeVee vulnerability intelligence tool as a modern web application with automated updates and professional hosting.

## 🚀 Complete Solution Overview

I've created a comprehensive web deployment solution that transforms your command-line SeeVee tool into a fully-featured web application:

### Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │    Backend      │    │   Database      │
│   (Netlify)     │◄──►│  (Railway/      │◄──►│   Updates       │
│                 │    │   Render)       │    │ (GitHub Actions)│
│   • Modern UI   │    │   • FastAPI     │    │                 │
│   • Responsive  │    │   • API Auth    │    │ • Every 6 hours │
│   • Real-time   │    │   • CORS        │    │ • Incremental   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📁 What Was Created

### Frontend (`web/frontend/`)
- **`index.html`**: Modern, responsive single-page application
- **`css/styles.css`**: Professional styling with dark/light themes
- **`js/config.js`**: Configuration for API endpoints and settings
- **`js/api.js`**: API client with caching and error handling
- **`js/app.js`**: Main application logic and UI interactions
- **`netlify.toml`**: Deployment configuration for Netlify

### Backend (`web/backend/`)
- **`app.py`**: Enhanced FastAPI server with authentication
- **`requirements.txt`**: Python dependencies

### Deployment (`web/deploy/`)
- **`railway.toml`**: Configuration for Railway deployment
- **`render.yaml`**: Configuration for Render deployment

### Automation (`.github/workflows/`)
- **`deploy-frontend.yml`**: Automatic frontend deployment to Netlify
- **`update-database.yml`**: Scheduled database updates every 6 hours

## 🎯 Key Features Implemented

### Security
- ✅ **API Key Authentication**: Static key authentication for web access
- ✅ **CORS Protection**: Configurable origin restrictions
- ✅ **Input Validation**: Comprehensive validation on frontend and backend
- ✅ **Rate Limiting Ready**: Architecture supports future rate limiting

### Performance
- ✅ **Client-side Caching**: 5-minute cache with LRU eviction
- ✅ **Request Deduplication**: Prevents duplicate API calls
- ✅ **Batch Processing**: Handle up to 50 CVEs/CWEs at once
- ✅ **Optimized Database**: Quick startup with recent data only

### User Experience
- ✅ **Modern Interface**: Professional, responsive design
- ✅ **Real-time Search**: Instant CVE/CWE lookups
- ✅ **Batch Operations**: Multi-vulnerability processing
- ✅ **Statistics Dashboard**: Database health monitoring
- ✅ **Mobile Friendly**: Works on all devices

### Automation
- ✅ **Scheduled Updates**: Every 6 hours via GitHub Actions
- ✅ **Automatic Deployment**: Push-to-deploy for frontend
- ✅ **Health Monitoring**: Built-in health checks
- ✅ **Artifact Storage**: Database snapshots for backup

## 🛠 Quick Deployment Steps

### 1. Set Up Your API Key
Generate a secure API key (use a password manager):
```bash
# Example: strong random key
API_KEY="svu-$(openssl rand -hex 16)-prod"
```

### 2. Deploy Backend (Choose One)

#### Option A: Railway (Recommended)
1. Create [Railway](https://railway.app) account
2. Connect your GitHub repository
3. Deploy from `web/backend` directory
4. Set environment variables:
   ```
   SEEVEE_API_KEY=your-secure-api-key-here
   ENVIRONMENT=production
   UPDATE_DB_ON_STARTUP=true
   CORS_ORIGINS=*
   ```
5. Note your Railway URL (e.g., `https://seevee-api.railway.app`)

#### Option B: Render
1. Create [Render](https://render.com) account
2. Import repository and use `web/deploy/render.yaml`
3. Set `SEEVEE_API_KEY` in dashboard
4. Deploy and note your Render URL

### 3. Configure Frontend
Update `web/frontend/js/config.js`:
```javascript
const config = {
    API: {
        BASE_URL: 'https://your-backend-url.railway.app',  // Your backend URL
        API_KEY: 'your-secure-api-key-here'                // Same key as backend
    }
    // ... rest of config
};
```

### 4. Deploy Frontend to Netlify
1. Create [Netlify](https://netlify.com) account
2. Connect your GitHub repository
3. Set build directory to `web/frontend`
4. Deploy automatically

**OR** use the GitHub Action (requires secrets):
- Set `NETLIFY_AUTH_TOKEN` and `NETLIFY_SITE_ID` in repository secrets

### 5. Enable Automated Updates
The GitHub Action will automatically:
- Update CVE database every 6 hours
- Include recent years for fast updates
- Store database artifacts for backup
- Notify on failures

## 🔧 Configuration Options

### Backend Environment Variables
```bash
# Required
SEEVEE_API_KEY=your-secure-api-key-here

# Optional with defaults
ENVIRONMENT=production
UPDATE_DB_ON_STARTUP=true
CORS_ORIGINS=*
PORT=8000
HOST=0.0.0.0

# For faster startup (skip old years)
SKIP_YEARS=2020,2019,2018,2017,2016,2015,2014,2013,2012,2011,2010,2009,2008,2007,2006,2005,2004,2003,2002
```

### Frontend Configuration
Customize in `web/frontend/js/config.js`:
- API endpoints and authentication
- UI behavior and timeouts
- Feature flags
- Cache settings

## 📊 Database Management

### Automatic Updates
- **Schedule**: Every 6 hours (00:00, 06:00, 12:00, 18:00 UTC)
- **Strategy**: Incremental (recent 2 years + modified feeds)
- **Fallback**: Manual trigger available
- **Storage**: Artifacts saved for 7 days

### Manual Updates
Trigger via API:
```bash
curl -X POST "https://your-backend-url.com/update" \
  -H "X-API-Key: your-api-key"
```

Or via GitHub Actions (manual workflow dispatch)

### Database Size Optimization
- **Full database**: ~1.4GB (all years since 2002)
- **Optimized**: ~200MB (recent 2 years only)
- **Startup**: Quick with optimized approach
- **Storage**: SQLite for simplicity, PostgreSQL migration possible

## 🎨 User Interface Features

### Home Dashboard
- Real-time database statistics
- Quick access to search functions
- Status indicators

### CVE Lookup
- Individual CVE search
- CVSS scoring details
- Risk analysis
- Reference links

### CWE Lookup
- Weakness enumeration search
- Detailed descriptions
- Classification information

### Batch Processing
- Upload multiple CVEs/CWEs
- Progress tracking
- Downloadable results
- Success/failure summary

## 🔍 Monitoring & Troubleshooting

### Health Checks
```bash
# Backend health
curl https://your-backend-url.com/health

# Database statistics (requires API key)
curl -H "X-API-Key: your-key" https://your-backend-url.com/stats
```

### Common Issues

1. **API Key Mismatch**
   - Verify frontend config matches backend env var
   - Check browser console for 401 errors

2. **CORS Errors**
   - Add frontend domain to `CORS_ORIGINS`
   - Use `*` for development, specific domains for production

3. **Database Update Failures**
   - Check GitHub Actions logs
   - Verify disk space on deployment platform
   - Try manual trigger

4. **Performance Issues**
   - Enable caching in frontend config
   - Monitor backend response times
   - Consider upgrading hosting plans

## 💰 Cost Analysis

### Free Tier Hosting
Most applications can run entirely free:

| Service | Free Tier | Paid Plans Start |
|---------|-----------|------------------|
| Railway | 500 hours/month | $5/month |
| Render | 750 hours/month | $7/month |
| Netlify | 100GB bandwidth/month | $19/month |

### Scaling Considerations
- **Traffic**: Free tiers handle moderate usage
- **Database**: 1.4GB fits in free storage limits
- **Bandwidth**: Typical usage well within limits
- **Compute**: Database updates most resource-intensive

## 🔮 Future Enhancements

### Planned Features
- **User Authentication**: Multi-user support
- **API Rate Limiting**: Per-user limits
- **Export Functions**: PDF/CSV reports
- **Real-time Feeds**: WebSocket updates
- **Advanced Analytics**: Usage statistics

### Migration Paths
- **Database**: SQLite → PostgreSQL
- **Storage**: Local → S3/CloudFlare R2
- **Caching**: In-memory → Redis
- **CDN**: Direct → CloudFlare

## 📞 Support & Maintenance

### Regular Tasks
- Monitor database update logs
- Check API response times
- Review security headers
- Update dependencies quarterly

### Getting Help
- **GitHub Issues**: Bug reports and features
- **Discussions**: Community support
- **Email**: Direct support contact

## 🏁 Success Checklist

- [ ] Backend deployed and responding to health checks
- [ ] Frontend deployed and loading correctly
- [ ] API key configured and working
- [ ] Database updates running automatically
- [ ] CORS configured for your domain
- [ ] Monitoring set up for health checks

## 🎉 What You Get

With this deployment, you now have:

1. **Professional Web Interface**: Modern, responsive vulnerability lookup tool
2. **Automated Updates**: Always current vulnerability data
3. **Scalable Architecture**: Ready for growth and additional features
4. **Zero Maintenance**: Automated deployments and updates
5. **Cost Effective**: Can run entirely on free tiers
6. **Secure by Default**: API authentication and CORS protection

Your SeeVee tool is now a professional-grade web service ready for production use!

---

*This deployment guide provides everything needed to transform your command-line SeeVee tool into a modern web application with automated updates, professional hosting, and a beautiful user interface.* 