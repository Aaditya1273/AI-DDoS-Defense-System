// Threat Analytics Visualization Module
document.addEventListener('DOMContentLoaded', function() {
    // Only initialize if we're on a page with the threat analysis tab
    if (!document.getElementById('threat-analysis')) return;

    // Initialize charts when the threat analysis tab is shown
    document.querySelector('.neo-sidebar-link[data-tab="threat-analysis"]').addEventListener('click', function() {
        setTimeout(() => {
            initThreatAnalytics();
        }, 300);
    });

    // Initialize threat map controls
    initThreatMapControls();

    // Initialize attack log search and filters
    initAttackLogControls();
});

// Initialize threat map controls (zoom, reset)
function initThreatMapControls() {
    const zoomIn = document.getElementById('zoom-in-map');
    const zoomOut = document.getElementById('zoom-out-map');
    const resetMap = document.getElementById('reset-map');
    
    if (!zoomIn || !zoomOut || !resetMap) return;
    
    let zoomLevel = 1;
    
    zoomIn.addEventListener('click', () => {
        zoomLevel = Math.min(zoomLevel + 0.2, 2.5);
        applyMapZoom();
    });
    
    zoomOut.addEventListener('click', () => {
        zoomLevel = Math.max(zoomLevel - 0.2, 0.5);
        applyMapZoom();
    });
    
    resetMap.addEventListener('click', () => {
        zoomLevel = 1;
        applyMapZoom();
        
        // Also reset the map position if it was panned
        const map = document.getElementById('threat-map');
        if (map) {
            map.style.transform = `scale(${zoomLevel})`;
        }
    });
    
    function applyMapZoom() {
        const map = document.getElementById('threat-map');
        if (map) {
            map.style.transform = `scale(${zoomLevel})`;
            map.style.transition = 'transform 0.3s ease';
        }
    }
}

// Initialize attack log search and filters
function initAttackLogControls() {
    const searchInput = document.getElementById('attack-search');
    const typeFilter = document.getElementById('attack-type-filter');
    
    if (!searchInput || !typeFilter) return;
    
    searchInput.addEventListener('input', filterAttackLog);
    typeFilter.addEventListener('change', filterAttackLog);
    
    function filterAttackLog() {
        const searchTerm = searchInput.value.toLowerCase();
        const filterType = typeFilter.value;
        const rows = document.querySelectorAll('#attack-log-table tr');
        
        let visibleRows = 0;
        
        rows.forEach(row => {
            const attackType = row.children[2]?.textContent.toLowerCase() || '';
            const sourceIP = row.children[1]?.textContent.toLowerCase() || '';
            const timestamp = row.children[0]?.textContent.toLowerCase() || '';
            
            const matchesSearch = !searchTerm || 
                sourceIP.includes(searchTerm) || 
                attackType.includes(searchTerm) ||
                timestamp.includes(searchTerm);
                
            const matchesFilter = filterType === 'all' || 
                attackType.includes(filterType.replace('-', ' '));
            
            if (matchesSearch && matchesFilter) {
                row.style.display = '';
                visibleRows++;
            } else {
                row.style.display = 'none';
            }
        });
        
        // Update the showing records count
        const showingRecords = document.getElementById('showing-records');
        if (showingRecords) {
            showingRecords.textContent = visibleRows;
        }
    }
}

// Initialize all threat analytics visualizations
function initThreatAnalytics() {
    // Hide the loading indicator and show the actual map
    const mapLoading = document.getElementById('map-loading');
    if (mapLoading) {
        mapLoading.style.display = 'none';
    }
    
    // Initialize the threat map with random attack points
    initThreatMap();
    
    // Initialize the attack vector chart
    initAttackVectorChart();
    
    // Initialize threat confidence gauge
    initThreatGauge();
    
    // Initialize attack timeline chart
    initAttackTimelineChart();
    
    // Initialize attack classification chart
    initAttackClassificationChart();
    
    // Populate top attack countries list
    populateTopAttackCountries();
}

// Initialize the threat map with random attack points
function initThreatMap() {
    const mapContainer = document.getElementById('threat-map');
    if (!mapContainer) return;
    
    // Create a simple world map using SVG
    mapContainer.innerHTML = `
        <svg viewBox="0 0 1000 500" class="w-full h-full">
            <!-- World map path simplified for demo -->
            <path d="M200,100 Q400,50 600,100 T800,150 Q600,200 400,250 T200,300 Q400,350 600,400 T800,450" 
                  fill="none" stroke="rgba(35, 200, 255, 0.3)" stroke-width="1"/>
            
            <!-- Attack points will be added dynamically -->
            <g id="attack-points"></g>
            
            <!-- Attack lines (from source to target) -->
            <g id="attack-lines"></g>
        </svg>
    `;
    
    // Generate random attack points
    const attackPoints = document.getElementById('attack-points');
    const attackLines = document.getElementById('attack-lines');
    
    // Target point (center of our infrastructure)
    const targetX = 500;
    const targetY = 250;
    
    // Generate 50 random attack points
    for (let i = 0; i < 50; i++) {
        // Random position
        const x = Math.random() * 900 + 50;
        const y = Math.random() * 400 + 50;
        
        // Random size based on attack intensity
        const size = Math.random() * 5 + 2;
        
        // Random color based on threat level
        const colors = ['#FF5252', '#FFB629', '#FF4081'];
        const color = colors[Math.floor(Math.random() * colors.length)];
        
        // Create the attack point
        const attackPoint = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        attackPoint.setAttribute('cx', x);
        attackPoint.setAttribute('cy', y);
        attackPoint.setAttribute('r', size);
        attackPoint.setAttribute('fill', color);
        attackPoint.setAttribute('class', 'pulse-animation');
        
        attackPoints.appendChild(attackPoint);
        
        // Create attack line from source to target
        const attackLine = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        attackLine.setAttribute('x1', x);
        attackLine.setAttribute('y1', y);
        attackLine.setAttribute('x2', targetX);
        attackLine.setAttribute('y2', targetY);
        attackLine.setAttribute('stroke', color);
        attackLine.setAttribute('stroke-width', size / 3);
        attackLine.setAttribute('stroke-opacity', '0.3');
        attackLine.setAttribute('stroke-dasharray', '5,5');
        attackLine.setAttribute('class', 'pulse-animation');
        
        attackLines.appendChild(attackLine);
    }
    
    // Create the target point (our infrastructure)
    const targetPoint = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    targetPoint.setAttribute('cx', targetX);
    targetPoint.setAttribute('cy', targetY);
    targetPoint.setAttribute('r', 10);
    targetPoint.setAttribute('fill', '#1CEFAF');
    targetPoint.setAttribute('stroke', '#1CEFAF');
    targetPoint.setAttribute('stroke-width', 5);
    targetPoint.setAttribute('stroke-opacity', '0.3');
    
    attackPoints.appendChild(targetPoint);
    
    // Add hover effects and interactivity via JavaScript
    mapContainer.querySelectorAll('circle').forEach(circle => {
        circle.addEventListener('mouseover', function() {
            if (this !== targetPoint) {
                this.setAttribute('r', parseInt(this.getAttribute('r')) * 1.5);
            }
        });
        
        circle.addEventListener('mouseout', function() {
            if (this !== targetPoint) {
                this.setAttribute('r', parseInt(this.getAttribute('r')) / 1.5);
            }
        });
    });
}

// Initialize the attack vector chart
function initAttackVectorChart() {
    const ctx = document.getElementById('attack-vector-chart');
    if (!ctx) return;
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['SYN Flood', 'UDP Amplification', 'HTTP Flood', 'Other'],
            datasets: [{
                data: [42, 28, 15, 15],
                backgroundColor: [
                    'rgba(255, 82, 82, 0.8)',
                    'rgba(255, 182, 41, 0.8)',
                    'rgba(35, 200, 255, 0.8)',
                    'rgba(255, 64, 129, 0.8)'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.label}: ${context.raw}%`;
                        }
                    }
                }
            }
        }
    });
}

// Initialize the threat confidence gauge
function initThreatGauge() {
    const gaugeContainer = document.getElementById('threat-gauge');
    if (!gaugeContainer) return;
    
    // Clear existing content
    gaugeContainer.innerHTML = '';
    
    // SVG gauge implementation
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 100 100');
    svg.setAttribute('class', 'w-full h-full');
    
    // Background arc
    const bgArc = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    bgArc.setAttribute('d', 'M10,50 A40,40 0 1,1 90,50');
    bgArc.setAttribute('fill', 'none');
    bgArc.setAttribute('stroke', 'rgba(255,255,255,0.1)');
    bgArc.setAttribute('stroke-width', '8');
    bgArc.setAttribute('stroke-linecap', 'round');
    
    // Value arc (dynamic)
    const valueArc = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    
    // Set the value (0-100)
    const value = 78;
    const angle = value / 100 * 180;
    
    // Calculate end point of arc based on angle
    const endX = 50 - 40 * Math.cos((180 - angle) * Math.PI / 180);
    const endY = 50 - 40 * Math.sin((180 - angle) * Math.PI / 180);
    
    valueArc.setAttribute('d', `M10,50 A40,40 0 ${angle > 90 ? 1 : 0},1 ${endX},${endY}`);
    valueArc.setAttribute('fill', 'none');
    
    // Color gradient based on value
    let arcColor;
    if (value < 40) {
        arcColor = '#1CEFAF'; // Low (good)
    } else if (value < 70) {
        arcColor = '#F5C346'; // Medium (warning)
    } else {
        arcColor = '#FF5252'; // High (danger)
    }
    
    valueArc.setAttribute('stroke', arcColor);
    valueArc.setAttribute('stroke-width', '8');
    valueArc.setAttribute('stroke-linecap', 'round');
    
    // Add tick marks
    const ticks = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    
    for (let i = 0; i <= 10; i++) {
        const tickAngle = i * 18;
        const tickStartX = 50 - 35 * Math.cos((180 - tickAngle) * Math.PI / 180);
        const tickStartY = 50 - 35 * Math.sin((180 - tickAngle) * Math.PI / 180);
        const tickEndX = 50 - 45 * Math.cos((180 - tickAngle) * Math.PI / 180);
        const tickEndY = 50 - 45 * Math.sin((180 - tickAngle) * Math.PI / 180);
        
        const tick = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        tick.setAttribute('x1', tickStartX);
        tick.setAttribute('y1', tickStartY);
        tick.setAttribute('x2', tickEndX);
        tick.setAttribute('y2', tickEndY);
        tick.setAttribute('stroke', 'rgba(255,255,255,0.3)');
        tick.setAttribute('stroke-width', i % 5 === 0 ? '2' : '1');
        
        ticks.appendChild(tick);
    }
    
    // Add everything to SVG
    svg.appendChild(bgArc);
    svg.appendChild(valueArc);
    svg.appendChild(ticks);
    
    // Add to container
    gaugeContainer.appendChild(svg);
    
    // Update the displayed value
    const valueEl = document.getElementById('threat-confidence-value');
    if (valueEl) {
        valueEl.textContent = `${value}%`;
        valueEl.className = `text-3xl font-mono font-bold ${
            value < 40 ? 'text-success' : value < 70 ? 'text-warning' : 'text-danger'
        }`;
    }
}

// Initialize the attack timeline chart
function initAttackTimelineChart() {
    const ctx = document.getElementById('attack-timeline-chart');
    if (!ctx) return;
    
    // Generate hourly data for the last 24 hours
    const labels = [];
    const attackData = [];
    const mitigatedData = [];
    
    for (let i = 23; i >= 0; i--) {
        const hour = new Date();
        hour.setHours(hour.getHours() - i);
        
        // Format hour as HH:00
        labels.push(hour.getHours().toString().padStart(2, '0') + ':00');
        
        // Random data with some patterns
        let attacks = Math.floor(Math.random() * 150) + 20;
        
        // Add a peak in the middle
        if (i >= 10 && i <= 14) {
            attacks += 100;
        }
        
        attackData.push(attacks);
        mitigatedData.push(Math.floor(attacks * (0.9 + Math.random() * 0.1))); // 90-100% mitigated
    }
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Attack Attempts',
                    data: attackData,
                    borderColor: 'rgba(255, 82, 82, 1)',
                    backgroundColor: 'rgba(255, 82, 82, 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'Mitigated',
                    data: mitigatedData,
                    borderColor: 'rgba(28, 239, 175, 1)',
                    backgroundColor: 'rgba(28, 239, 175, 0.1)',
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        boxWidth: 12,
                        color: 'rgba(226, 232, 240, 0.7)'
                    }
                }
            }
        }
    });
    
    // Calculate and display totals
    const totalAttacks = attackData.reduce((sum, val) => sum + val, 0);
    const peakAttackRate = Math.max(...attackData);
    const avgAttackRate = Math.round(totalAttacks / attackData.length);
    
    document.getElementById('total-attacks')?.textContent = totalAttacks.toLocaleString();
    document.getElementById('peak-attack-rate')?.textContent = `${peakAttackRate}/hour`;
    document.getElementById('avg-attack-rate')?.textContent = `${avgAttackRate}/hour`;
}

// Initialize the attack classification chart
function initAttackClassificationChart() {
    const ctx = document.getElementById('attack-classification-chart');
    if (!ctx) return;
    
    new Chart(ctx, {
        type: 'radar',
        data: {
            labels: [
                'SYN Flood', 
                'UDP Amplification', 
                'HTTP Flood', 
                'Slowloris', 
                'NTP Amplification',
                'DNS Amplification'
            ],
            datasets: [{
                label: 'Volume (GB)',
                data: [42, 28, 14, 8, 18, 22],
                backgroundColor: 'rgba(255, 82, 82, 0.2)',
                borderColor: 'rgba(255, 82, 82, 1)',
                pointBackgroundColor: 'rgba(255, 82, 82, 1)',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: 'rgba(255, 82, 82, 1)'
            }, {
                label: 'Frequency (#)',
                data: [35, 15, 25, 32, 12, 8],
                backgroundColor: 'rgba(35, 200, 255, 0.2)',
                borderColor: 'rgba(35, 200, 255, 1)',
                pointBackgroundColor: 'rgba(35, 200, 255, 1)',
                pointBorderColor: '#fff',
                pointHoverBackgroundColor: '#fff',
                pointHoverBorderColor: 'rgba(35, 200, 255, 1)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    angleLines: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    pointLabels: {
                        color: 'rgba(226, 232, 240, 0.7)'
                    },
                    ticks: {
                        backdropColor: 'transparent',
                        color: 'rgba(226, 232, 240, 0.7)'
                    }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        boxWidth: 12,
                        color: 'rgba(226, 232, 240, 0.7)'
                    }
                }
            }
        }
    });
}

// Populate the top attack countries list
function populateTopAttackCountries() {
    const container = document.getElementById('top-attack-countries');
    if (!container) return;
    
    // Clear existing content
    container.innerHTML = '';
    
    // Sample data
    const topCountries = [
        { name: 'United States', count: 437, icon: '🇺🇸' },
        { name: 'China', count: 356, icon: '🇨🇳' },
        { name: 'Russia', count: 289, icon: '🇷🇺' },
        { name: 'Brazil', count: 183, icon: '🇧🇷' },
        { name: 'India', count: 147, icon: '🇮🇳' }
    ];
    
    // Create list items
    topCountries.forEach(country => {
        const listItem = document.createElement('li');
        listItem.className = 'flex justify-between items-center';
        
        listItem.innerHTML = `
            <div class="flex items-center gap-2">
                <span>${country.icon}</span>
                <span>${country.name}</span>
            </div>
            <span class="font-mono">${country.count}</span>
        `;
        
        container.appendChild(listItem);
    });
}

// Time range selection handler
document.getElementById('time-range-select')?.addEventListener('change', function() {
    // In a real application, this would reload the data for the selected time range
    const timeRange = this.value;
    console.log(`Selected time range: ${timeRange}`);
    
    // Show a notification about the changed time range
    showNotification(`Data updated for ${getTimeRangeText(timeRange)}`, 'info');
    
    // Reinitialize charts with new data
    initThreatAnalytics();
});

// Helper to get human-readable time range text
function getTimeRangeText(timeRange) {
    switch(timeRange) {
        case '1h': return 'the last hour';
        case '6h': return 'the last 6 hours';
        case '24h': return 'the last 24 hours';
        case '7d': return 'the last 7 days';
        default: return timeRange;
    }
}

// Export report button handler
document.getElementById('export-threat-report')?.addEventListener('click', function() {
    // In a real application, this would generate and download a PDF report
    showNotification('Threat report is being generated...', 'info');
    
    // Simulate report generation delay
    setTimeout(() => {
        showNotification('Threat report downloaded successfully', 'success');
    }, 2000);
}); 