// Configuration for SeeVee Frontend
const config = {
    // API Configuration
    API: {
        // Base URL for the backend API
        // This will be different for development vs production
        BASE_URL: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
            ? 'http://localhost:8000'  // Development
            : 'https://seevee-api.railway.app',  // Production (update with your actual backend URL)
        
        // API key for authentication
        // In production, this should be handled more securely
        API_KEY: 'your-static-api-key-here',  // Replace with your actual API key
        
        // Request timeout in milliseconds
        TIMEOUT: 30000,
        
        // Maximum retries for failed requests
        MAX_RETRIES: 3,
        
        // Endpoints
        ENDPOINTS: {
            CVE: '/cve',
            CVE_BATCH: '/cve/batch',
            CWE: '/cwe',
            CWE_BATCH: '/cwe/batch',
            STATS: '/stats',
            HEALTH: '/health'
        }
    },
    
    // UI Configuration
    UI: {
        // Default page to show on load
        DEFAULT_SECTION: 'home',
        
        // Animation duration in milliseconds
        ANIMATION_DURATION: 300,
        
        // Toast display duration in milliseconds
        TOAST_DURATION: 5000,
        
        // Maximum number of results to display in batch operations
        MAX_BATCH_RESULTS: 50,
        
        // Maximum number of references to show per CVE
        MAX_REFERENCES: 10,
        
        // Debounce delay for search inputs
        SEARCH_DEBOUNCE: 500
    },
    
    // Feature flags
    FEATURES: {
        // Enable/disable real-time statistics updates
        REAL_TIME_STATS: true,
        
        // Enable/disable batch operations
        BATCH_OPERATIONS: true,
        
        // Enable/disable advanced CVSS details
        CVSS_DETAILS: true,
        
        // Enable/disable risk analysis
        RISK_ANALYSIS: true,
        
        // Enable/disable export functionality (future feature)
        EXPORT_RESULTS: false
    },
    
    // Cache configuration
    CACHE: {
        // Enable/disable local caching
        ENABLED: true,
        
        // Cache duration in milliseconds (5 minutes)
        DURATION: 5 * 60 * 1000,
        
        // Maximum cache size (number of items)
        MAX_SIZE: 100
    },
    
    // Environment detection
    ENVIRONMENT: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'development'
        : 'production',
    
    // Version information
    VERSION: '1.0.0',
    
    // Contact/support information
    SUPPORT: {
        EMAIL: 'support@vuln.tools',  // Replace with your support email
        GITHUB: 'https://github.com/altjerry0/seevee',  // Replace with your GitHub repo
        DOCS: 'https://github.com/altjerry0/seevee#readme'  // Replace with your documentation
    }
};

// Utility functions for configuration
const configUtils = {
    /**
     * Get the full API URL for an endpoint
     */
    getApiUrl: (endpoint) => {
        return `${config.API.BASE_URL}${endpoint}`;
    },
    
    /**
     * Check if a feature is enabled
     */
    isFeatureEnabled: (feature) => {
        return config.FEATURES[feature] === true;
    },
    
    /**
     * Get environment-specific configuration
     */
    getEnvironmentConfig: () => {
        return {
            isDevelopment: config.ENVIRONMENT === 'development',
            isProduction: config.ENVIRONMENT === 'production',
            enableDebugLogging: config.ENVIRONMENT === 'development'
        };
    },
    
    /**
     * Validate configuration on startup
     */
    validate: () => {
        const errors = [];
        
        // Check required configuration
        if (!config.API.BASE_URL) {
            errors.push('API.BASE_URL is required');
        }
        
        if (!config.API.API_KEY || config.API.API_KEY === 'your-static-api-key-here') {
            console.warn('Warning: Using default API key. Please update config.API.API_KEY');
        }
        
        // Validate URLs
        try {
            new URL(config.API.BASE_URL);
        } catch (e) {
            errors.push('API.BASE_URL must be a valid URL');
        }
        
        if (errors.length > 0) {
            console.error('Configuration validation errors:', errors);
            return false;
        }
        
        return true;
    }
};

// Validate configuration on load
document.addEventListener('DOMContentLoaded', () => {
    if (!configUtils.validate()) {
        console.error('Configuration validation failed. Please check your settings.');
    } else {
        console.log(`SeeVee v${config.VERSION} - Configuration loaded successfully`);
        if (configUtils.getEnvironmentConfig().enableDebugLogging) {
            console.log('Configuration:', config);
        }
    }
});

// Export configuration for use in other modules
window.SeeVeeConfig = config;
window.SeeVeeConfigUtils = configUtils; 