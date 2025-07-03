# SeeVee Web Deployment

This directory contains the web deployment version of SeeVee, consisting of a modern frontend and enhanced backend API designed for cloud deployment.

## Architecture

```
web/
├── frontend/          # Static web application (deploys to Netlify)
│   ├── index.html     # Main HTML file
│   ├── css/           # Stylesheets
│   ├── js/            # JavaScript application logic
│   └── netlify.toml   # Netlify deployment configuration
├── backend/           # Enhanced API server (deploys to Railway/Render)
│   ├── app.py         # FastAPI application
│   └── requirements.txt
└── deploy/            # Deployment configurations
    ├── railway.toml   # Railway configuration
    └── render.yaml    # Render configuration
```

## Features

### Frontend
- 🎨 Modern, responsive web interface
- 🔍 Real-time CVE and CWE lookup
- 📊 Database statistics dashboard
- 🚀 Batch vulnerability processing
- 📱 Mobile-friendly design
- ⚡ Client-side caching for performance

### Backend
- 🔐 API key authentication
- 🌐 CORS-enabled for web frontends
- 📈 Database statistics endpoints
- 🔄 Automatic database updates
- 🎯 Optimized for cloud deployment
- 📊 Health monitoring endpoints

## Quick Start

### 1. Deploy the Backend

#### Option A: Railway (Recommended)
1. Fork this repository
2. Create a [Railway](https://railway.app) account
3. Connect your GitHub repository
4. Deploy from the `web/backend` directory
5. Set environment variables:
   ```
   SEEVEE_API_KEY=your-secure-api-key-here
   ENVIRONMENT=production
   UPDATE_DB_ON_STARTUP=true
   ```

#### Option B: Render
1. Create a [Render](https://render.com) account
2. Use the `web/deploy/render.yaml` configuration
3. Set the `SEEVEE_API_KEY` in the Render dashboard

### 2. Deploy the Frontend

#### Netlify (Recommended)
1. Create a [Netlify](https://netlify.com) account
2. Connect your GitHub repository
3. Set build directory to `web/frontend`
4. Update `web/frontend/js/config.js` with your backend URL
5. Deploy automatically via GitHub integration

### 3. Configure API Key

Update the API key in your frontend configuration:

```javascript
// web/frontend/js/config.js
API_KEY: 'your-secure-api-key-here'
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SEEVEE_API_KEY` | API authentication key | `seevee-default-key-change-me` | Yes |
| `ENVIRONMENT` | Deployment environment | `production` | No |
| `UPDATE_DB_ON_STARTUP` | Update database on startup | `false` | No |
| `CORS_ORIGINS` | Allowed CORS origins | `*` | No |
| `PORT` | Server port | `8000` | No |
| `HOST` | Server host | `0.0.0.0` | No |

### Frontend Configuration

Edit `web/frontend/js/config.js` to customize:

```javascript
const config = {
    API: {
        BASE_URL: 'https://your-backend-url.com',
        API_KEY: 'your-secure-api-key-here'
    },
    // ... other settings
};
```

## Database Management

### Scheduled Updates

The system includes automatic database updates every 6 hours via GitHub Actions:

- **Incremental updates**: Recent 2 years of CVE data
- **Full updates**: All historical data (can be triggered manually)
- **CWE updates**: Latest CWE definitions from MITRE

### Manual Updates

Trigger updates via the API:

```bash
curl -X POST "https://your-backend-url.com/update" \
  -H "X-API-Key: your-api-key"
```

## Security

### API Key Management

1. **Generate a secure API key** (use a password manager)
2. **Set as environment variable** in your deployment platform
3. **Update frontend configuration** with the same key
4. **Never commit API keys** to version control

### CORS Configuration

For production, limit CORS origins:

```bash
CORS_ORIGINS=https://your-frontend-domain.netlify.app,https://your-custom-domain.com
```

## Monitoring

### Health Checks

- **Backend health**: `GET /health`
- **Database stats**: `GET /stats` (requires API key)

### GitHub Actions

Monitor deployment and database update status:

- Frontend deployment: Automatic on push to `web/frontend/**`
- Database updates: Every 6 hours + manual trigger
- Artifacts: Database snapshots stored for 7 days

## Development

### Local Development

1. **Backend**:
   ```bash
   cd web/backend
   pip install -r requirements.txt
   export SEEVEE_API_KEY=test-key
   export ENVIRONMENT=development
   python app.py
   ```

2. **Frontend**:
   ```bash
   cd web/frontend
   # Serve with any static file server
   python -m http.server 8080
   ```

### Testing

Test the API endpoints:

```bash
# Health check
curl https://your-backend-url.com/health

# CVE lookup
curl -H "X-API-Key: your-key" \
     "https://your-backend-url.com/cve/CVE-2021-44228"

# Database stats
curl -H "X-API-Key: your-key" \
     "https://your-backend-url.com/stats"
```

## Deployment Platforms

### Supported Platforms

| Platform | Type | Cost | Database Storage | Auto-scaling |
|----------|------|------|------------------|--------------|
| Railway | Backend | Free tier available | Persistent disk | Yes |
| Render | Backend | Free tier available | Persistent disk | Yes |
| Netlify | Frontend | Free tier available | N/A | N/A |
| Vercel | Frontend | Free tier available | N/A | N/A |

### Database Considerations

- **SQLite**: Simple, included, good for moderate traffic
- **Size**: ~1.4GB for full CVE database
- **Performance**: Sufficient for most use cases
- **Migration**: Can upgrade to PostgreSQL later if needed

## Troubleshooting

### Common Issues

1. **API Key Errors**:
   - Verify key matches between frontend and backend
   - Check environment variables are set correctly

2. **CORS Errors**:
   - Update `CORS_ORIGINS` to include your frontend domain
   - Check browser console for detailed error messages

3. **Database Issues**:
   - Monitor disk space (database is ~1.4GB)
   - Check update logs in GitHub Actions

4. **Performance Issues**:
   - Enable caching in frontend configuration
   - Consider CDN for static assets
   - Monitor API response times

### Logs and Monitoring

- **Railway**: Built-in logging dashboard
- **Render**: Application logs in dashboard
- **Netlify**: Deploy logs and function logs
- **GitHub Actions**: Workflow logs for database updates

## Cost Estimation

### Free Tier Usage

Most applications can run entirely on free tiers:

- **Railway**: 500 hours/month free
- **Render**: 750 hours/month free
- **Netlify**: 100GB bandwidth/month free

### Scaling Considerations

For high-traffic applications:

- **Backend**: Upgrade to paid plans for more resources
- **Database**: Consider PostgreSQL migration
- **CDN**: Use Cloudflare or similar for static assets
- **Caching**: Implement Redis for API response caching

## Contributing

1. Fork the repository
2. Create a feature branch
3. Test locally
4. Submit a pull request

## Support

- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: General questions and community support
- **Email**: [Your support email here]

## License

This project maintains the same license as the main SeeVee project. See the main LICENSE file for details. 