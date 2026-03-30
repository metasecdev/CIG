# Cyber Intelligence Gateway Dashboard

The CIG system now includes a comprehensive web dashboard accessible through the FastAPI server.

## Dashboard Features

### Main Dashboard (`/`)
- System overview with key metrics (alerts, indicators, feeds, captures)
- Recent alerts table
- System status indicators
- Navigation sidebar

### System Status (`/dashboard/status`)
- Detailed system status information
- Intelligence feed status (MISP, pfBlocker, AbuseIPDB)
- PCAP capture status
- Component status overview

### Health Check (`/dashboard/health`)
- Database health metrics
- Feed connectivity status
- Capture system status
- System performance indicators

### Events & Alerts (`/dashboard/events`)
- Comprehensive alerts table with filtering
- Alert statistics by severity
- Alert details modal
- Pagination support

### Reports (`/dashboard/reports`)
- Security report generation
- Quick report actions (24h, 7-day, HTML reports)
- Report history
- Export functionality

## Accessing the Dashboard

1. Start the CIG server:
```bash
cd /path/to/cig
cig_venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

2. Open your browser and navigate to:
- Main Dashboard: `http://localhost:8000/`
- Status Dashboard: `http://localhost:8000/dashboard/status`
- Health Dashboard: `http://localhost:8000/dashboard/health`
- Events Dashboard: `http://localhost:8000/dashboard/events`
- Reports Dashboard: `http://localhost:8000/dashboard/reports`

## Technical Implementation

- **Framework**: FastAPI with Jinja2 templates
- **Styling**: Bootstrap 5 with custom CSS
- **JavaScript**: Vanilla JS with dashboard utilities
- **Responsive**: Mobile-friendly design
- **Real-time**: Auto-refresh capabilities

## Files Created

### Templates
- `templates/dashboard.html` - Main dashboard
- `templates/status.html` - System status
- `templates/health.html` - Health checks
- `templates/events.html` - Events & alerts
- `templates/reports.html` - Reports
- `templates/error.html` - Error handling

### Static Assets
- `static/dashboard.css` - Custom styling
- `static/dashboard.js` - Dashboard functionality

### Backend
- Updated `app/api/routes.py` with dashboard endpoints
- Added template and static file serving
- Error handling for uninitialized systems

## API Endpoints

The dashboard uses existing API endpoints:
- `/api/health` - Health check
- `/api/stats` - System statistics
- `/api/alerts` - Alert data
- `/api/status` - System status
- `/api/reports/security` - Security reports
- `/api/reports/html` - HTML reports

## Features

- **Responsive Design**: Works on desktop and mobile
- **Real-time Updates**: Auto-refresh functionality
- **Interactive Elements**: Modals, buttons, forms
- **Error Handling**: Graceful error pages
- **Navigation**: Consistent sidebar navigation
- **Data Visualization**: Tables, cards, badges for data display

## Browser Compatibility

- Chrome/Edge: Full support
- Firefox: Full support
- Safari: Full support
- Mobile browsers: Responsive support

## Troubleshooting

If the dashboard doesn't load:
1. Ensure the server is running on the correct port
2. Check browser console for JavaScript errors
3. Verify template and static files exist
4. Check server logs for FastAPI errors

If data doesn't display:
1. Ensure the database is initialized
2. Check that threat feeds are configured
3. Verify API endpoints are responding
4. Check browser network tab for failed requests