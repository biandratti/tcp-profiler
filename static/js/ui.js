// UI Manager for Huginn Network Profiler
class UIManager {
    constructor() {
        this.elements = {};
        this.currentProfiles = new Map();
        this.currentFilter = 'all';
        this.searchQuery = '';
        this.isModalOpen = false;
        this.activityFeed = [];
        this.maxActivityItems = 100;
        
        this.init();
    }

    // Initialize UI elements and event handlers
    init() {
        this.cacheElements();
        this.setupEventHandlers();
        this.updateConnectionStatus(false);
        this.showEmptyState();
    }

    // Cache DOM elements
    cacheElements() {
        this.elements = {
            // Header elements
            statusIndicator: document.getElementById('statusIndicator'),
            statusText: document.getElementById('statusText'),
            toggleConnection: document.getElementById('toggleConnection'),
            
            // Stats elements
            totalProfiles: document.getElementById('totalProfiles'),
            tcpProfiles: document.getElementById('tcpProfiles'),
            httpProfiles: document.getElementById('httpProfiles'),
            tlsProfiles: document.getElementById('tlsProfiles'),
            completeProfiles: document.getElementById('completeProfiles'),
            
            // Controls elements
            searchInput: document.getElementById('searchInput'),
            searchBtn: document.getElementById('searchBtn'),
            filterType: document.getElementById('filterType'),
            clearProfiles: document.getElementById('clearProfiles'),
            refreshProfiles: document.getElementById('refreshProfiles'),
            
            // Profiles elements
            profilesCount: document.getElementById('profilesCount'),
            profilesList: document.getElementById('profilesList'),
            emptyState: document.getElementById('emptyState'),
            startCollector: document.getElementById('startCollector'),
            
            // Activity elements
            activityFeed: document.getElementById('activityFeed'),
            clearActivity: document.getElementById('clearActivity'),
            
            // Modal elements
            profileModal: document.getElementById('profileModal'),
            modalTitle: document.getElementById('modalTitle'),
            modalBody: document.getElementById('modalBody'),
            modalClose: document.getElementById('modalClose')
        };
    }

    // Setup event handlers
    setupEventHandlers() {
        // Connection toggle
        this.elements.toggleConnection?.addEventListener('click', () => {
            this.toggleConnection();
        });

        // Search functionality
        this.elements.searchBtn?.addEventListener('click', () => {
            this.performSearch();
        });

        this.elements.searchInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.performSearch();
            }
        });

        // Filter functionality
        this.elements.filterType?.addEventListener('change', (e) => {
            this.currentFilter = e.target.value;
            this.filterProfiles();
        });

        // Control buttons
        this.elements.clearProfiles?.addEventListener('click', () => {
            this.clearAllProfiles();
        });

        this.elements.refreshProfiles?.addEventListener('click', () => {
            this.refreshProfiles();
        });

        this.elements.startCollector?.addEventListener('click', () => {
            this.startCollector();
        });

        // Activity controls
        this.elements.clearActivity?.addEventListener('click', () => {
            this.clearActivity();
        });

        // Modal controls
        this.elements.modalClose?.addEventListener('click', () => {
            this.closeModal();
        });

        this.elements.profileModal?.addEventListener('click', (e) => {
            if (e.target === this.elements.profileModal) {
                this.closeModal();
            }
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.isModalOpen) {
                this.closeModal();
            }
        });
    }

    // Update connection status
    updateConnectionStatus(connected) {
        if (!this.elements.statusIndicator || !this.elements.statusText || !this.elements.toggleConnection) {
            return;
        }

        if (connected) {
            this.elements.statusIndicator.className = 'status-indicator connected';
            this.elements.statusText.textContent = 'Connected';
            this.elements.toggleConnection.textContent = 'Disconnect';
        } else {
            this.elements.statusIndicator.className = 'status-indicator';
            this.elements.statusText.textContent = 'Disconnected';
            this.elements.toggleConnection.textContent = 'Connect';
        }
    }

    // Update connection status with connecting state
    updateConnectionStatusConnecting() {
        if (!this.elements.statusIndicator || !this.elements.statusText) {
            return;
        }

        this.elements.statusIndicator.className = 'status-indicator connecting';
        this.elements.statusText.textContent = 'Connecting...';
    }

    // Toggle connection
    toggleConnection() {
        if (window.wsManager.isConnected) {
            window.wsManager.disconnect();
        } else {
            this.updateConnectionStatusConnecting();
            window.wsManager.connect();
        }
    }

    // Update statistics
    updateStats(stats) {
        if (!stats) return;

        if (this.elements.totalProfiles) {
            this.elements.totalProfiles.textContent = stats.total_profiles || 0;
        }
        if (this.elements.tcpProfiles) {
            this.elements.tcpProfiles.textContent = stats.tcp_profiles || 0;
        }
        if (this.elements.httpProfiles) {
            this.elements.httpProfiles.textContent = stats.http_profiles || 0;
        }
        if (this.elements.tlsProfiles) {
            this.elements.tlsProfiles.textContent = stats.tls_profiles || 0;
        }
        if (this.elements.completeProfiles) {
            this.elements.completeProfiles.textContent = stats.complete_profiles || 0;
        }
    }

    // Update profiles display
    updateProfiles(profilesData) {
        if (!profilesData || !profilesData.profiles) {
            this.showEmptyState();
            return;
        }

        const profiles = profilesData.profiles;
        const profileCount = Object.keys(profiles).length;

        // Update profiles count
        if (this.elements.profilesCount) {
            this.elements.profilesCount.textContent = `${profileCount} profile${profileCount !== 1 ? 's' : ''}`;
        }

        // Store current profiles
        this.currentProfiles.clear();
        for (const [key, profile] of Object.entries(profiles)) {
            this.currentProfiles.set(key, profile);
        }

        if (profileCount === 0) {
            this.showEmptyState();
        } else {
            this.hideEmptyState();
            this.renderProfiles(profiles);
        }
    }

    // Render profiles list
    renderProfiles(profiles) {
        if (!this.elements.profilesList) return;

        const profilesArray = Object.entries(profiles);
        const filteredProfiles = this.applyCurrentFilters(profilesArray);

        this.elements.profilesList.innerHTML = '';

        filteredProfiles.forEach(([key, profile]) => {
            const profileCard = this.createProfileCard(key, profile);
            this.elements.profilesList.appendChild(profileCard);
        });
    }

    // Create profile card element
    createProfileCard(key, profile) {
        const card = document.createElement('div');
        card.className = 'profile-card';
        card.dataset.profileKey = key;

        const timestamp = profile.timestamp ? new Date(profile.timestamp).toLocaleString() : 'Unknown';
        const qualityScore = profile.quality_score || 0;

        card.innerHTML = `
            <div class="profile-header">
                <div class="profile-ip">${key}</div>
                <div class="profile-timestamp">${timestamp}</div>
            </div>
            <div class="profile-data">
                ${this.createDataSection('TCP Analysis', profile.tcp_analysis, 'tcp')}
                ${this.createDataSection('HTTP Analysis', profile.http_analysis, 'http')}
                ${this.createDataSection('TLS Analysis', profile.tls_analysis, 'tls')}
                <div class="data-section">
                    <div class="data-title">Quality Score</div>
                    <div class="data-content">
                        <div class="data-item">
                            <span class="data-label">Score:</span>
                            <span class="data-value">${qualityScore.toFixed(2)}</span>
                        </div>
                    </div>
                </div>
            </div>
        `;

        card.addEventListener('click', () => {
            this.showProfileModal(key, profile);
        });

        return card;
    }

    // Create data section for profile card
    createDataSection(title, data, type) {
        if (!data) {
            return `
                <div class="data-section ${type}">
                    <div class="data-title">${title}</div>
                    <div class="data-content">
                        <div class="data-item">
                            <span class="data-label">Status:</span>
                            <span class="data-value">No data</span>
                        </div>
                    </div>
                </div>
            `;
        }

        let content = '';
        const maxItems = 3;
        let itemCount = 0;

        for (const [key, value] of Object.entries(data)) {
            if (itemCount >= maxItems) break;
            
            let displayValue = value;
            if (typeof value === 'object' && value !== null) {
                displayValue = JSON.stringify(value).substring(0, 50) + '...';
            } else if (typeof value === 'string' && value.length > 30) {
                displayValue = value.substring(0, 30) + '...';
            }

            content += `
                <div class="data-item">
                    <span class="data-label">${this.formatKey(key)}:</span>
                    <span class="data-value">${displayValue}</span>
                </div>
            `;
            itemCount++;
        }

        return `
            <div class="data-section ${type}">
                <div class="data-title">${title}</div>
                <div class="data-content">
                    ${content}
                </div>
            </div>
        `;
    }

    // Format key for display
    formatKey(key) {
        return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    // Show profile modal
    showProfileModal(key, profile) {
        if (!this.elements.profileModal) return;

        this.elements.modalTitle.textContent = `Profile Details - ${key}`;
        this.elements.modalBody.innerHTML = this.createDetailedProfileView(profile);
        this.elements.profileModal.classList.add('active');
        this.isModalOpen = true;
    }

    // Close modal
    closeModal() {
        if (!this.elements.profileModal) return;

        this.elements.profileModal.classList.remove('active');
        this.isModalOpen = false;
    }

    // Create detailed profile view
    createDetailedProfileView(profile) {
        let html = '<div class="profile-details">';

        // Basic info
        html += `
            <div class="detail-section">
                <h4>Basic Information</h4>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">Timestamp:</span>
                        <span class="detail-value">${profile.timestamp || 'Unknown'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Quality Score:</span>
                        <span class="detail-value">${(profile.quality_score || 0).toFixed(2)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Complete:</span>
                        <span class="detail-value">${profile.is_complete ? 'Yes' : 'No'}</span>
                    </div>
                </div>
            </div>
        `;

        // TCP Analysis
        if (profile.tcp_analysis) {
            html += this.createDetailSection('TCP Analysis', profile.tcp_analysis);
        }

        // HTTP Analysis
        if (profile.http_analysis) {
            html += this.createDetailSection('HTTP Analysis', profile.http_analysis);
        }

        // TLS Analysis
        if (profile.tls_analysis) {
            html += this.createDetailSection('TLS Analysis', profile.tls_analysis);
        }

        html += '</div>';
        return html;
    }

    // Create detail section
    createDetailSection(title, data) {
        let html = `
            <div class="detail-section">
                <h4>${title}</h4>
                <div class="detail-grid">
        `;

        for (const [key, value] of Object.entries(data)) {
            const displayValue = typeof value === 'object' ? 
                JSON.stringify(value, null, 2) : 
                String(value);

            html += `
                <div class="detail-item">
                    <span class="detail-label">${this.formatKey(key)}:</span>
                    <span class="detail-value">${displayValue}</span>
                </div>
            `;
        }

        html += '</div></div>';
        return html;
    }

    // Apply current filters
    applyCurrentFilters(profilesArray) {
        let filtered = profilesArray;

        // Apply type filter
        if (this.currentFilter !== 'all') {
            filtered = filtered.filter(([key, profile]) => {
                switch (this.currentFilter) {
                    case 'tcp':
                        return profile.tcp_analysis;
                    case 'http':
                        return profile.http_analysis;
                    case 'tls':
                        return profile.tls_analysis;
                    case 'complete':
                        return profile.is_complete;
                    default:
                        return true;
                }
            });
        }

        // Apply search filter
        if (this.searchQuery) {
            const query = this.searchQuery.toLowerCase();
            filtered = filtered.filter(([key, profile]) => {
                return key.toLowerCase().includes(query) ||
                       JSON.stringify(profile).toLowerCase().includes(query);
            });
        }

        return filtered;
    }

    // Filter profiles
    filterProfiles() {
        const profiles = Object.fromEntries(this.currentProfiles);
        this.renderProfiles(profiles);
    }

    // Perform search
    performSearch() {
        if (!this.elements.searchInput) return;

        this.searchQuery = this.elements.searchInput.value.trim();
        this.filterProfiles();
    }

    // Show empty state
    showEmptyState() {
        if (this.elements.emptyState) {
            this.elements.emptyState.style.display = 'flex';
        }
        if (this.elements.profilesList) {
            this.elements.profilesList.style.display = 'none';
        }
    }

    // Hide empty state
    hideEmptyState() {
        if (this.elements.emptyState) {
            this.elements.emptyState.style.display = 'none';
        }
        if (this.elements.profilesList) {
            this.elements.profilesList.style.display = 'block';
        }
    }

    // Clear all profiles
    async clearAllProfiles() {
        if (confirm('Are you sure you want to clear all profiles?')) {
            try {
                await window.huginnAPI.clearProfiles();
                this.addActivity('Cleared all profiles', 'removed');
                this.refreshProfiles();
            } catch (error) {
                console.error('Failed to clear profiles:', error);
                this.showError('Failed to clear profiles');
            }
        }
    }

    // Refresh profiles
    async refreshProfiles() {
        try {
            const profiles = await window.huginnAPI.getProfiles();
            this.updateProfiles(profiles);
            
            const stats = await window.huginnAPI.getStats();
            this.updateStats(stats);
        } catch (error) {
            console.error('Failed to refresh profiles:', error);
            this.showError('Failed to refresh profiles');
        }
    }

    // Start collector
    startCollector() {
        this.addActivity('Collector start requested', 'created');
        // This would typically trigger the collector via API
        // For now, we'll just show a message
        alert('Collector would be started here. This requires backend implementation.');
    }

    // Add activity item
    addActivity(message, type = 'created') {
        const activity = {
            message,
            type,
            timestamp: new Date().toISOString()
        };

        this.activityFeed.unshift(activity);
        
        // Limit activity feed size
        if (this.activityFeed.length > this.maxActivityItems) {
            this.activityFeed = this.activityFeed.slice(0, this.maxActivityItems);
        }

        this.renderActivity();
    }

    // Render activity feed
    renderActivity() {
        if (!this.elements.activityFeed) return;

        this.elements.activityFeed.innerHTML = '';

        this.activityFeed.forEach(activity => {
            const item = document.createElement('div');
            item.className = 'activity-item';
            
            const time = new Date(activity.timestamp).toLocaleTimeString();
            
            item.innerHTML = `
                <div class="activity-message">
                    <span class="activity-type ${activity.type}">${activity.type}</span>
                    ${activity.message}
                </div>
                <div class="activity-time">${time}</div>
            `;

            this.elements.activityFeed.appendChild(item);
        });
    }

    // Clear activity
    clearActivity() {
        this.activityFeed = [];
        this.renderActivity();
    }

    // Show error message
    showError(message) {
        // Simple error display - could be enhanced with toast notifications
        console.error(message);
        alert(message);
    }

    // Show success message
    showSuccess(message) {
        // Simple success display - could be enhanced with toast notifications
        console.log(message);
    }
}

// Export singleton instance
window.uiManager = new UIManager(); 