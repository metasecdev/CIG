// Cyber Intelligence Gateway Dashboard JavaScript

// Auto-refresh functionality
let autoRefreshInterval;

function startAutoRefresh(interval = 30000) { // 30 seconds default
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
    }
    autoRefreshInterval = setInterval(() => {
        refreshDashboard();
    }, interval);
}

function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
}

function refreshDashboard() {
    // Only refresh if we're on the main dashboard
    if (window.location.pathname === '/' || window.location.pathname === '/dashboard') {
        location.reload();
    }
}

// Initialize when document is ready
document.addEventListener('DOMContentLoaded', function() {
    // Start auto-refresh for main dashboard
    if (window.location.pathname === '/' || window.location.pathname === '/dashboard') {
        startAutoRefresh();
    }

    // Add loading indicators for buttons
    const buttons = document.querySelectorAll('button[onclick]');
    buttons.forEach(button => {
        button.addEventListener('click', function() {
            if (!this.classList.contains('btn-loading')) {
                this.classList.add('btn-loading');
                this.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status"></span>' + this.innerHTML;
                setTimeout(() => {
                    this.classList.remove('btn-loading');
                }, 2000);
            }
        });
    });
});

// Utility functions
function formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    try {
        const date = new Date(timestamp);
        return date.toLocaleString();
    } catch (e) {
        return timestamp;
    }
}

function formatNumber(num) {
    if (num === null || num === undefined) return '0';
    return num.toLocaleString();
}

function showToast(message, type = 'info') {
    // Simple toast implementation
    const toast = document.createElement('div');
    toast.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    toast.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    toast.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.body.appendChild(toast);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (toast.parentNode) {
            toast.remove();
        }
    }, 5000);
}

// Error handling
window.addEventListener('error', function(e) {
    console.error('Dashboard error:', e.error);
    showToast('An error occurred. Please refresh the page.', 'danger');
});

window.addEventListener('unhandledrejection', function(e) {
    console.error('Unhandled promise rejection:', e.reason);
    showToast('An unexpected error occurred.', 'danger');
});

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl/Cmd + R to refresh
    if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
        e.preventDefault();
        location.reload();
    }

    // Ctrl/Cmd + H to go home
    if ((e.ctrlKey || e.metaKey) && e.key === 'h') {
        e.preventDefault();
        window.location.href = '/';
    }
});

// Performance monitoring
let pageLoadTime = performance.now();

window.addEventListener('load', function() {
    const loadTime = performance.now() - pageLoadTime;
    console.log(`Dashboard loaded in ${loadTime.toFixed(2)}ms`);

    // Send load time to analytics if available
    if (typeof gtag !== 'undefined') {
        gtag('event', 'page_load_time', {
            event_category: 'performance',
            value: Math.round(loadTime)
        });
    }
});

// Export functions for global use
window.CIGDashboard = {
    startAutoRefresh,
    stopAutoRefresh,
    refreshDashboard,
    formatTimestamp,
    formatNumber,
    showToast
};