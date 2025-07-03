// SeeVee API Client
class SeeVeeAPI {
    constructor() {
        this.config = window.SeeVeeConfig;
        this.cache = new Map();
        this.requestQueue = new Map();
    }

    /**
     * Make a generic API request with retry logic and caching
     */
    async makeRequest(endpoint, options = {}) {
        const url = `${this.config.API.BASE_URL}${endpoint}`;
        const requestId = this.generateRequestId(url, options);

        // Check if request is already in progress
        if (this.requestQueue.has(requestId)) {
            return this.requestQueue.get(requestId);
        }

        // Check cache for GET requests
        if ((!options.method || options.method === 'GET') && this.config.CACHE.ENABLED) {
            const cached = this.getFromCache(requestId);
            if (cached) {
                return cached;
            }
        }

        // Create the request promise
        const requestPromise = this.executeRequest(url, options);
        
        // Store in queue to prevent duplicate requests
        this.requestQueue.set(requestId, requestPromise);

        try {
            const result = await requestPromise;
            
            // Cache successful GET requests
            if ((!options.method || options.method === 'GET') && this.config.CACHE.ENABLED) {
                this.setCache(requestId, result);
            }
            
            return result;
        } finally {
            // Remove from queue when done
            this.requestQueue.delete(requestId);
        }
    }

    /**
     * Execute the actual HTTP request with retry logic
     */
    async executeRequest(url, options) {
        const defaultOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': this.config.API.API_KEY,
                'Accept': 'application/json'
            },
            timeout: this.config.API.TIMEOUT
        };

        const requestOptions = { ...defaultOptions, ...options };
        
        // Merge headers
        if (options.headers) {
            requestOptions.headers = { ...defaultOptions.headers, ...options.headers };
        }

        let lastError;
        
        // Retry logic
        for (let attempt = 1; attempt <= this.config.API.MAX_RETRIES; attempt++) {
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), requestOptions.timeout);
                
                const response = await fetch(url, {
                    ...requestOptions,
                    signal: controller.signal
                });

                clearTimeout(timeoutId);

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                const data = await response.json();
                return data;
                
            } catch (error) {
                lastError = error;
                
                // Don't retry for certain errors
                if (error.name === 'AbortError') {
                    throw new Error('Request timeout');
                }
                
                if (error.message.includes('HTTP 4')) {
                    // Client errors (4xx) shouldn't be retried
                    throw error;
                }
                
                // Wait before retry (exponential backoff)
                if (attempt < this.config.API.MAX_RETRIES) {
                    const delay = Math.pow(2, attempt - 1) * 1000; // 1s, 2s, 4s
                    await this.sleep(delay);
                }
            }
        }
        
        throw lastError;
    }

    /**
     * Generate a unique request ID for caching and deduplication
     */
    generateRequestId(url, options) {
        const key = url + JSON.stringify(options.body || '') + (options.method || 'GET');
        return btoa(key).replace(/[^a-zA-Z0-9]/g, '');
    }

    /**
     * Cache management
     */
    getFromCache(key) {
        if (!this.config.CACHE.ENABLED) return null;
        
        const cached = this.cache.get(key);
        if (!cached) return null;
        
        // Check if cache entry is expired
        if (Date.now() - cached.timestamp > this.config.CACHE.DURATION) {
            this.cache.delete(key);
            return null;
        }
        
        return cached.data;
    }

    setCache(key, data) {
        if (!this.config.CACHE.ENABLED) return;
        
        // Implement LRU eviction
        if (this.cache.size >= this.config.CACHE.MAX_SIZE) {
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }
        
        this.cache.set(key, {
            data: data,
            timestamp: Date.now()
        });
    }

    /**
     * Clear the cache
     */
    clearCache() {
        this.cache.clear();
    }

    /**
     * Utility function for delays
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // API Methods

    /**
     * Get CVE information
     */
    async getCVE(cveId, options = {}) {
        const params = new URLSearchParams();
        if (options.includeCvssDetails) params.append('include_cvss_details', 'true');
        if (options.includeRiskAnalysis) params.append('include_risk_analysis', 'true');
        if (options.includeReferences !== undefined) params.append('include_references', options.includeReferences.toString());
        
        const queryString = params.toString();
        const endpoint = `${this.config.API.ENDPOINTS.CVE}/${cveId}${queryString ? '?' + queryString : ''}`;
        
        return this.makeRequest(endpoint);
    }

    /**
     * Batch CVE lookup
     */
    async batchCVE(cveIds, options = {}) {
        const payload = {
            cve_ids: Array.isArray(cveIds) ? cveIds : [cveIds],
            include_cvss_details: options.includeCvssDetails || false,
            include_risk_analysis: options.includeRiskAnalysis || false,
            include_references: options.includeReferences !== undefined ? options.includeReferences : true
        };

        return this.makeRequest(this.config.API.ENDPOINTS.CVE_BATCH, {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    }

    /**
     * Get CWE information
     */
    async getCWE(cweId) {
        const endpoint = `${this.config.API.ENDPOINTS.CWE}/${cweId}`;
        return this.makeRequest(endpoint);
    }

    /**
     * Batch CWE lookup
     */
    async batchCWE(cweIds) {
        const payload = {
            cwe_ids: Array.isArray(cweIds) ? cweIds : [cweIds]
        };

        return this.makeRequest(this.config.API.ENDPOINTS.CWE_BATCH, {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    }

    /**
     * Get database statistics
     */
    async getStats() {
        return this.makeRequest(this.config.API.ENDPOINTS.STATS);
    }

    /**
     * Health check
     */
    async healthCheck() {
        return this.makeRequest(this.config.API.ENDPOINTS.HEALTH);
    }
}

// Request utilities
class RequestUtils {
    /**
     * Parse CVE IDs from text input
     */
    static parseCVEIds(text) {
        if (!text) return [];
        
        // Split by commas, newlines, or whitespace
        const ids = text.split(/[\s,\n]+/)
            .map(id => id.trim().toUpperCase())
            .filter(id => id.length > 0);
        
        // Validate CVE format and add CVE- prefix if missing
        return ids.map(id => {
            if (id.match(/^\d{4}-\d+$/)) {
                return `CVE-${id}`;
            }
            if (id.match(/^CVE-\d{4}-\d+$/)) {
                return id;
            }
            return id; // Return as-is, let backend validate
        });
    }

    /**
     * Parse CWE IDs from text input
     */
    static parseCWEIds(text) {
        if (!text) return [];
        
        // Split by commas, newlines, or whitespace
        const ids = text.split(/[\s,\n]+/)
            .map(id => id.trim().toUpperCase())
            .filter(id => id.length > 0);
        
        // Validate CWE format and add CWE- prefix if missing
        return ids.map(id => {
            if (id.match(/^\d+$/)) {
                return `CWE-${id}`;
            }
            if (id.match(/^CWE-\d+$/)) {
                return id;
            }
            return id; // Return as-is, let backend validate
        });
    }

    /**
     * Validate CVE ID format
     */
    static isValidCVE(cveId) {
        if (!cveId) return false;
        return /^CVE-\d{4}-\d+$/i.test(cveId.trim());
    }

    /**
     * Validate CWE ID format
     */
    static isValidCWE(cweId) {
        if (!cweId) return false;
        const cleaned = cweId.trim().toUpperCase();
        return /^(CWE-)?\d+$/.test(cleaned);
    }

    /**
     * Format date string for display
     */
    static formatDate(dateString) {
        if (!dateString) return 'N/A';
        
        try {
            const date = new Date(dateString);
            return date.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        } catch (e) {
            return dateString;
        }
    }

    /**
     * Format large numbers with commas
     */
    static formatNumber(num) {
        if (typeof num !== 'number') return num;
        return num.toLocaleString();
    }

    /**
     * Get CVSS severity color class
     */
    static getSeverityClass(severity) {
        if (!severity) return '';
        
        switch (severity.toLowerCase()) {
            case 'critical': return 'severity-critical';
            case 'high': return 'severity-high';
            case 'medium': return 'severity-medium';
            case 'low': return 'severity-low';
            default: return '';
        }
    }

    /**
     * Truncate text to specified length
     */
    static truncateText(text, maxLength = 100) {
        if (!text || text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    }

    /**
     * Escape HTML to prevent XSS
     */
    static escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Error handling utilities
class APIError extends Error {
    constructor(message, status, endpoint) {
        super(message);
        this.name = 'APIError';
        this.status = status;
        this.endpoint = endpoint;
    }
}

// Initialize global API instance
window.SeeVeeAPI = new SeeVeeAPI();
window.RequestUtils = RequestUtils;
window.APIError = APIError;

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SeeVeeAPI, RequestUtils, APIError };
} 