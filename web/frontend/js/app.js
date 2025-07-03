// SeeVee Main Application
class SeeVeeApp {
    constructor() {
        this.api = window.SeeVeeAPI;
        this.config = window.SeeVeeConfig;
        this.utils = window.RequestUtils;
        this.currentSection = this.config.UI.DEFAULT_SECTION;
        this.debounceTimers = new Map();
        
        this.init();
    }

    /**
     * Initialize the application
     */
    init() {
        this.setupEventListeners();
        this.showSection(this.currentSection);
        this.loadInitialData();
        
        // Setup periodic stats updates if enabled
        if (this.config.FEATURES.REAL_TIME_STATS) {
            setInterval(() => this.updateStats(), 60000); // Update every minute
        }
    }

    /**
     * Setup all event listeners
     */
    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const section = link.getAttribute('href').substring(1);
                this.showSection(section);
            });
        });

        // Mobile navigation toggle
        const navToggle = document.querySelector('.nav-toggle');
        if (navToggle) {
            navToggle.addEventListener('click', () => {
                // Mobile navigation logic would go here
                // For now, this is just a placeholder
            });
        }

        // Form submissions
        this.setupFormListeners();
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch (e.key) {
                    case '/':
                    case 'k':
                        e.preventDefault();
                        this.focusSearchInput();
                        break;
                }
            }
        });
    }

    /**
     * Setup form event listeners
     */
    setupFormListeners() {
        // CVE lookup form
        const cveInput = document.getElementById('cve-input');
        if (cveInput) {
            cveInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    this.lookupCVE();
                }
            });
        }

        // CWE lookup form
        const cweInput = document.getElementById('cwe-input');
        if (cweInput) {
            cweInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    this.lookupCWE();
                }
            });
        }

        // Batch form submissions
        const batchCveInput = document.getElementById('batch-cve-input');
        if (batchCveInput) {
            batchCveInput.addEventListener('keydown', (e) => {
                if (e.ctrlKey && e.key === 'Enter') {
                    e.preventDefault();
                    this.batchLookupCVE();
                }
            });
        }

        const batchCweInput = document.getElementById('batch-cwe-input');
        if (batchCweInput) {
            batchCweInput.addEventListener('keydown', (e) => {
                if (e.ctrlKey && e.key === 'Enter') {
                    e.preventDefault();
                    this.batchLookupCWE();
                }
            });
        }
    }

    /**
     * Show a specific section and update navigation
     */
    showSection(sectionId) {
        // Hide all sections
        document.querySelectorAll('.section').forEach(section => {
            section.classList.remove('active');
        });

        // Show target section
        const targetSection = document.getElementById(sectionId);
        if (targetSection) {
            targetSection.classList.add('active');
            this.currentSection = sectionId;
        }

        // Update navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${sectionId}`) {
                link.classList.add('active');
            }
        });

        // Load section-specific data
        this.loadSectionData(sectionId);
    }

    /**
     * Load initial application data
     */
    async loadInitialData() {
        try {
            await this.updateStats();
        } catch (error) {
            console.error('Error loading initial data:', error);
        }
    }

    /**
     * Load section-specific data
     */
    loadSectionData(sectionId) {
        switch (sectionId) {
            case 'stats':
                this.updateStats();
                break;
            case 'home':
                this.updateStats(); // Update hero stats
                break;
        }
    }

    /**
     * Update statistics display
     */
    async updateStats() {
        try {
            const stats = await this.api.getStats();
            
            // Update hero stats
            this.updateElement('cve-count', this.utils.formatNumber(stats.cve_count));
            this.updateElement('cwe-count', this.utils.formatNumber(stats.cwe_count));
            this.updateElement('last-updated', stats.last_updated ? 
                this.utils.formatDate(stats.last_updated) : 'Never');

            // Update detailed stats section
            const statsContent = document.getElementById('stats-content');
            if (statsContent && this.currentSection === 'stats') {
                statsContent.innerHTML = this.renderStatsDetails(stats);
            }

        } catch (error) {
            console.error('Error updating stats:', error);
            this.showErrorToast('Failed to load statistics');
        }
    }

    /**
     * Render detailed statistics
     */
    renderStatsDetails(stats) {
        return `
            <div class="stat-card">
                <i class="fas fa-database"></i>
                <h3>CVE Database</h3>
                <div class="result-grid">
                    <div class="result-field">
                        <div class="result-field-label">Total CVE Records</div>
                        <div class="result-field-value">${this.utils.formatNumber(stats.cve_count)}</div>
                    </div>
                    <div class="result-field">
                        <div class="result-field-label">Database Size</div>
                        <div class="result-field-value">${stats.database_size_mb} MB</div>
                    </div>
                    <div class="result-field">
                        <div class="result-field-label">Last Updated</div>
                        <div class="result-field-value">${stats.last_updated ? this.utils.formatDate(stats.last_updated) : 'Never'}</div>
                    </div>
                </div>
            </div>
            <div class="stat-card">
                <i class="fas fa-bug"></i>
                <h3>CWE Database</h3>
                <div class="result-grid">
                    <div class="result-field">
                        <div class="result-field-label">Total CWE Records</div>
                        <div class="result-field-value">${this.utils.formatNumber(stats.cwe_count)}</div>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * CVE lookup functionality
     */
    async lookupCVE() {
        const input = document.getElementById('cve-input');
        const cveId = input.value.trim().toUpperCase();
        
        if (!cveId) {
            this.showErrorToast('Please enter a CVE identifier');
            return;
        }

        if (!this.utils.isValidCVE(cveId)) {
            this.showErrorToast('Invalid CVE format. Expected format: CVE-YYYY-NNNNN');
            return;
        }

        this.showLoading();

        try {
            const options = {
                includeCvssDetails: document.getElementById('include-cvss-details').checked,
                includeRiskAnalysis: document.getElementById('include-risk-analysis').checked,
                includeReferences: true
            };

            const result = await this.api.getCVE(cveId, options);
            this.displayCVEResult(result);
            this.showSuccessToast(`Found ${cveId}`);

        } catch (error) {
            console.error('CVE lookup error:', error);
            this.showErrorToast(`Failed to lookup ${cveId}: ${error.message}`);
            this.clearResults('cve-results');
        } finally {
            this.hideLoading();
        }
    }

    /**
     * CWE lookup functionality
     */
    async lookupCWE() {
        const input = document.getElementById('cwe-input');
        const cweId = input.value.trim().toUpperCase();
        
        if (!cweId) {
            this.showErrorToast('Please enter a CWE identifier');
            return;
        }

        if (!this.utils.isValidCWE(cweId)) {
            this.showErrorToast('Invalid CWE format. Expected format: CWE-NNN or just the number');
            return;
        }

        this.showLoading();

        try {
            const result = await this.api.getCWE(cweId);
            this.displayCWEResult(result);
            this.showSuccessToast(`Found ${cweId}`);

        } catch (error) {
            console.error('CWE lookup error:', error);
            this.showErrorToast(`Failed to lookup ${cweId}: ${error.message}`);
            this.clearResults('cwe-results');
        } finally {
            this.hideLoading();
        }
    }

    /**
     * Batch CVE lookup functionality
     */
    async batchLookupCVE() {
        const input = document.getElementById('batch-cve-input');
        const text = input.value.trim();
        
        if (!text) {
            this.showErrorToast('Please enter CVE identifiers');
            return;
        }

        const cveIds = this.utils.parseCVEIds(text);
        
        if (cveIds.length === 0) {
            this.showErrorToast('No valid CVE identifiers found');
            return;
        }

        if (cveIds.length > this.config.UI.MAX_BATCH_RESULTS) {
            this.showErrorToast(`Too many CVEs. Maximum allowed: ${this.config.UI.MAX_BATCH_RESULTS}`);
            return;
        }

        this.showLoading();

        try {
            const options = {
                includeCvssDetails: document.getElementById('batch-include-cvss').checked,
                includeRiskAnalysis: document.getElementById('batch-include-risk').checked,
                includeReferences: true
            };

            const result = await this.api.batchCVE(cveIds, options);
            this.displayBatchResults(result, 'CVE');
            this.showSuccessToast(`Processed ${cveIds.length} CVE(s)`);

        } catch (error) {
            console.error('Batch CVE lookup error:', error);
            this.showErrorToast(`Batch lookup failed: ${error.message}`);
            this.clearResults('batch-results');
        } finally {
            this.hideLoading();
        }
    }

    /**
     * Batch CWE lookup functionality
     */
    async batchLookupCWE() {
        const input = document.getElementById('batch-cwe-input');
        const text = input.value.trim();
        
        if (!text) {
            this.showErrorToast('Please enter CWE identifiers');
            return;
        }

        const cweIds = this.utils.parseCWEIds(text);
        
        if (cweIds.length === 0) {
            this.showErrorToast('No valid CWE identifiers found');
            return;
        }

        if (cweIds.length > this.config.UI.MAX_BATCH_RESULTS) {
            this.showErrorToast(`Too many CWEs. Maximum allowed: ${this.config.UI.MAX_BATCH_RESULTS}`);
            return;
        }

        this.showLoading();

        try {
            const result = await this.api.batchCWE(cweIds);
            this.displayBatchResults(result, 'CWE');
            this.showSuccessToast(`Processed ${cweIds.length} CWE(s)`);

        } catch (error) {
            console.error('Batch CWE lookup error:', error);
            this.showErrorToast(`Batch lookup failed: ${error.message}`);
            this.clearResults('batch-results');
        } finally {
            this.hideLoading();
        }
    }

    /**
     * Display CVE result
     */
    displayCVEResult(data) {
        const container = document.getElementById('cve-results');
        if (!container) return;

        container.innerHTML = this.renderCVEResult(data);
    }

    /**
     * Display CWE result
     */
    displayCWEResult(data) {
        const container = document.getElementById('cwe-results');
        if (!container) return;

        container.innerHTML = this.renderCWEResult(data);
    }

    /**
     * Display batch results
     */
    displayBatchResults(data, type) {
        const container = document.getElementById('batch-results');
        if (!container) return;

        let html = `
            <div class="result-item">
                <div class="result-header">
                    <h3>Batch ${type} Lookup Results</h3>
                    <div class="severity-badge severity-low">
                        ${data.summary.found} / ${data.summary.total} Found
                    </div>
                </div>
                <div class="result-grid">
                    <div class="result-field">
                        <div class="result-field-label">Processing Time</div>
                        <div class="result-field-value">${data.processing_time.toFixed(2)}s</div>
                    </div>
                    <div class="result-field">
                        <div class="result-field-label">Success Rate</div>
                        <div class="result-field-value">${((data.summary.found / data.summary.total) * 100).toFixed(1)}%</div>
                    </div>
                </div>
            </div>
        `;

        data.results.forEach(result => {
            if (result.found && result.data) {
                if (type === 'CVE') {
                    html += this.renderCVEResult(result.data);
                } else {
                    html += this.renderCWEResult(result.data);
                }
            } else {
                html += `
                    <div class="result-item">
                        <div class="result-header">
                            <h3 class="result-title">${result.cve_id || result.cwe_id}</h3>
                            <div class="severity-badge severity-medium">Not Found</div>
                        </div>
                        <p>${result.error || 'No data available'}</p>
                    </div>
                `;
            }
        });

        container.innerHTML = html;
    }

    /**
     * Render CVE result HTML
     */
    renderCVEResult(data) {
        const severityClass = this.utils.getSeverityClass(data.cvss_v3_severity || data.cvss_v2_severity);
        const severity = data.cvss_v3_severity || data.cvss_v2_severity || 'Unknown';
        const score = data.cvss_v3_score || data.cvss_v2_score || 'N/A';

        let html = `
            <div class="result-item">
                <div class="result-header">
                    <h3 class="result-title">${data.id}</h3>
                    <div class="severity-badge ${severityClass}">
                        ${severity} ${score !== 'N/A' ? `(${score})` : ''}
                    </div>
                </div>
                <div class="result-grid">
                    <div class="result-field">
                        <div class="result-field-label">Published</div>
                        <div class="result-field-value">${this.utils.formatDate(data.published)}</div>
                    </div>
                    <div class="result-field">
                        <div class="result-field-label">Last Modified</div>
                        <div class="result-field-value">${this.utils.formatDate(data.lastModified)}</div>
                    </div>
                    <div class="result-field">
                        <div class="result-field-label">Status</div>
                        <div class="result-field-value">${data.vulnStatus || 'N/A'}</div>
                    </div>
                    <div class="result-field">
                        <div class="result-field-label">Vendor</div>
                        <div class="result-field-value">${data.vendor_name || 'N/A'}</div>
                    </div>
                    <div class="result-field">
                        <div class="result-field-label">Product</div>
                        <div class="result-field-value">${data.product_name || 'N/A'}</div>
                    </div>
        `;

        if (data.cwe_ids && data.cwe_ids.length > 0) {
            html += `
                    <div class="result-field">
                        <div class="result-field-label">CWE IDs</div>
                        <div class="result-field-value">${data.cwe_ids.join(', ')}</div>
                    </div>
            `;
        }

        html += `</div>`;

        if (data.description) {
            html += `
                <div class="description-text">
                    <strong>Description:</strong><br>
                    ${this.utils.escapeHtml(data.description)}
                </div>
            `;
        }

        // CVSS Details
        if (data.cvss_v3_details || data.cvss_v2_details) {
            html += '<div class="result-grid">';
            
            if (data.cvss_v3_details) {
                html += this.renderCVSSDetails(data.cvss_v3_details, 'v3');
            }
            
            if (data.cvss_v2_details) {
                html += this.renderCVSSDetails(data.cvss_v2_details, 'v2');
            }
            
            html += '</div>';
        }

        // References
        if (data.references && data.references.length > 0) {
            const limitedRefs = data.references.slice(0, this.config.UI.MAX_REFERENCES);
            html += `
                <div class="references-section">
                    <strong>References:</strong>
                    <ul class="references-list">
            `;
            
            limitedRefs.forEach(ref => {
                html += `
                    <li>
                        <a href="${ref.url}" target="_blank" rel="noopener noreferrer">
                            <i class="fas fa-external-link-alt"></i>
                            ${this.utils.truncateText(ref.url, 80)}
                        </a>
                    </li>
                `;
            });
            
            if (data.references.length > this.config.UI.MAX_REFERENCES) {
                html += `<li><em>... and ${data.references.length - this.config.UI.MAX_REFERENCES} more references</em></li>`;
            }
            
            html += '</ul></div>';
        }

        html += '</div>';
        return html;
    }

    /**
     * Render CWE result HTML
     */
    renderCWEResult(data) {
        return `
            <div class="result-item">
                <div class="result-header">
                    <h3 class="result-title">${data.cwe_id}</h3>
                </div>
                <div class="result-grid">
                    <div class="result-field">
                        <div class="result-field-label">Name</div>
                        <div class="result-field-value">${data.name || 'N/A'}</div>
                    </div>
                    ${data.weakness_abstraction ? `
                    <div class="result-field">
                        <div class="result-field-label">Abstraction</div>
                        <div class="result-field-value">${data.weakness_abstraction}</div>
                    </div>
                    ` : ''}
                    ${data.status ? `
                    <div class="result-field">
                        <div class="result-field-label">Status</div>
                        <div class="result-field-value">${data.status}</div>
                    </div>
                    ` : ''}
                    <div class="result-field">
                        <div class="result-field-label">Source</div>
                        <div class="result-field-value">${data.source || 'N/A'}</div>
                    </div>
                </div>
                ${data.description ? `
                <div class="description-text">
                    <strong>Description:</strong><br>
                    ${this.utils.escapeHtml(data.description)}
                </div>
                ` : ''}
                ${data.extended_description ? `
                <div class="description-text">
                    <strong>Extended Description:</strong><br>
                    ${this.utils.escapeHtml(data.extended_description)}
                </div>
                ` : ''}
            </div>
        `;
    }

    /**
     * Render CVSS details
     */
    renderCVSSDetails(details, version) {
        const versionUpper = version.toUpperCase();
        
        return `
            <div class="result-field">
                <div class="result-field-label">CVSS ${versionUpper} Vector</div>
                <div class="result-field-value">${details.vectorString || 'N/A'}</div>
            </div>
            <div class="result-field">
                <div class="result-field-label">Exploitability Score</div>
                <div class="result-field-value">${details.exploitabilityScore || 'N/A'}</div>
            </div>
            <div class="result-field">
                <div class="result-field-label">Impact Score</div>
                <div class="result-field-value">${details.impactScore || 'N/A'}</div>
            </div>
        `;
    }

    /**
     * Show batch tab
     */
    showBatchTab(type) {
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        event.target.classList.add('active');

        // Update tab content
        document.querySelectorAll('.batch-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(`batch-${type}`).classList.add('active');
    }

    /**
     * Utility methods
     */
    updateElement(id, content) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = content;
        }
    }

    clearResults(containerId) {
        const container = document.getElementById(containerId);
        if (container) {
            container.innerHTML = '';
        }
    }

    focusSearchInput() {
        if (this.currentSection === 'cve-lookup') {
            document.getElementById('cve-input')?.focus();
        } else if (this.currentSection === 'cwe-lookup') {
            document.getElementById('cwe-input')?.focus();
        }
    }

    /**
     * Loading and toast methods
     */
    showLoading() {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            overlay.classList.add('show');
        }
    }

    hideLoading() {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            overlay.classList.remove('show');
        }
    }

    showErrorToast(message) {
        this.showToast(message, 'error');
    }

    showSuccessToast(message) {
        this.showToast(message, 'success');
    }

    showToast(message, type = 'success') {
        const toast = document.getElementById(`${type}-toast`);
        if (!toast) return;

        const messageElement = toast.querySelector('.toast-message');
        if (messageElement) {
            messageElement.textContent = message;
        }

        toast.classList.add('show');

        // Auto-hide after configured duration
        setTimeout(() => {
            this.hideToast(type);
        }, this.config.UI.TOAST_DURATION);
    }

    hideToast(type = null) {
        if (type) {
            const toast = document.getElementById(`${type}-toast`);
            if (toast) {
                toast.classList.remove('show');
            }
        } else {
            // Hide all toasts
            document.querySelectorAll('.toast').forEach(toast => {
                toast.classList.remove('show');
            });
        }
    }
}

// Global functions for HTML onclick handlers
function showSection(sectionId) {
    if (window.seeVeeApp) {
        window.seeVeeApp.showSection(sectionId);
    }
}

function lookupCVE() {
    if (window.seeVeeApp) {
        window.seeVeeApp.lookupCVE();
    }
}

function lookupCWE() {
    if (window.seeVeeApp) {
        window.seeVeeApp.lookupCWE();
    }
}

function batchLookupCVE() {
    if (window.seeVeeApp) {
        window.seeVeeApp.batchLookupCVE();
    }
}

function batchLookupCWE() {
    if (window.seeVeeApp) {
        window.seeVeeApp.batchLookupCWE();
    }
}

function showBatchTab(type) {
    if (window.seeVeeApp) {
        window.seeVeeApp.showBatchTab(type);
    }
}

function batchLookupCVE() {
    if (window.seeVeeApp) {
        window.seeVeeApp.batchLookupCVE();
    }
}

function batchLookupCWE() {
    if (window.seeVeeApp) {
        window.seeVeeApp.batchLookupCWE();
    }
}

function hideToast() {
    if (window.seeVeeApp) {
        window.seeVeeApp.hideToast();
    }
}

// Initialize the application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.seeVeeApp = new SeeVeeApp();
    console.log('SeeVee application initialized');
}); 