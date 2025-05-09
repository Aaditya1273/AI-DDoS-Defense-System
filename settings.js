// Settings functionality - executed when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Initialize theme selection
    document.querySelectorAll('.theme-option').forEach(theme => {
        theme.addEventListener('click', function() {
            // Remove selected class from all themes
            document.querySelectorAll('.theme-option').forEach(t => {
                t.classList.remove('selected');
                t.querySelector('.w-4.h-4').classList.remove('bg-primary');
            });
            
            // Add selected class to clicked theme
            this.classList.add('selected');
            this.querySelector('.w-4.h-4').classList.add('bg-primary');
            
            // Apply the theme
            applyTheme(this.id);
            
            // Save the setting
            saveSettings('theme', this.id);
        });
    });
    
    // Initialize toggle switches
    initializeToggles();
    
    // Initialize range sliders
    initializeRangeSliders();
    
    // Initialize radio buttons
    initializeRadioButtons();
    
    // Initialize save settings button
    document.getElementById('save-settings-btn')?.addEventListener('click', function() {
        // Save all settings
        saveAllSettings();
        
        // Show a notification that settings were saved
        showNotification('Settings saved successfully', 'success');
    });
    
    // Initialize email recipient input
    document.getElementById('email-recipient')?.addEventListener('blur', function() {
        saveSettings('email-recipients', this.value);
    });
    
    // Initialize log level dropdown
    document.getElementById('log-level')?.addEventListener('change', function() {
        saveSettings('log-level', this.value);
    });
    
    // Load saved settings when the Settings tab is shown
    document.querySelector('.neo-sidebar-link[data-tab="settings"]')?.addEventListener('click', function() {
        setTimeout(loadSavedSettings, 100); // Small delay to ensure tab is shown
    });
    
    // Initialize the resource monitor updates
    initResourceMonitor();
    
    // Initialize system action buttons
    initSystemActionButtons();
    
    // First load the theme immediately to prevent flickering
    loadSavedTheme();
    
    // Then load all other saved settings
    loadSavedSettings();
});

// Initialize system action buttons
function initSystemActionButtons() {
    // Reset Counters button
    document.getElementById('reset-counters-btn')?.addEventListener('click', function() {
        // Reset all counter elements
        document.getElementById('total-packets').textContent = '0';
        document.getElementById('suspicious-ips').textContent = '0';
        document.getElementById('blocked-ips').textContent = '0';
        document.getElementById('packets-per-sec').textContent = '0';
        document.getElementById('syn-packets').textContent = '0';
        document.getElementById('network-throughput').textContent = '0 MB/s';
        
        // Reset progress bars
        document.getElementById('packets-per-sec-bar').style.width = '0%';
        document.getElementById('syn-packets-bar').style.width = '0%';
        document.getElementById('network-throughput-bar').style.width = '0%';
        document.getElementById('confidenceBar').style.width = '0%';
        document.getElementById('confidenceValue').textContent = '0%';
        
        // Show notification
        showNotification('Counters reset successfully', 'success');
    });
    
    // Clear Logs button
    document.getElementById('clear-logs-btn')?.addEventListener('click', function() {
        // Simulate log clearing with a notification
        showNotification('System logs cleared', 'success');
    });
    
    // Export Config button
    document.getElementById('export-config-btn')?.addEventListener('click', function() {
        // Get current settings
        const settings = localStorage.getItem('cybershield-settings') || '{}';
        
        // Create a Blob with the settings data
        const blob = new Blob([settings], {type: 'application/json'});
        
        // Create download link
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'cybershield-settings.json';
        
        // Trigger download
        document.body.appendChild(a);
        a.click();
        
        // Cleanup
        setTimeout(() => {
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }, 100);
        
        // Show notification
        showNotification('Configuration exported successfully', 'success');
    });
    
    // Import Config button
    document.getElementById('import-config-btn')?.addEventListener('click', function() {
        // Create file input
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.json';
        
        // Handle file selection
        input.onchange = e => {
            const file = e.target.files[0];
            if (!file) return;
            
            const reader = new FileReader();
            reader.onload = event => {
                try {
                    // Validate JSON
                    const settings = JSON.parse(event.target.result);
                    
                    // Store the imported settings
                    localStorage.setItem('cybershield-settings', JSON.stringify(settings));
                    
                    // Apply the imported settings
                    loadSavedSettings();
                    
                    // Show notification
                    showNotification('Configuration imported successfully', 'success');
                } catch (error) {
                    // Show error notification
                    showNotification('Invalid configuration file', 'error');
                    console.error('Error importing settings:', error);
                }
            };
            reader.readAsText(file);
        };
        
        // Trigger file selection
        input.click();
    });
}

// Initialize all toggle switches
function initializeToggles() {
    const toggles = [
        'density-toggle', 'animation-toggle', 'email-toggle', 'sms-toggle', 
        'desktop-toggle', 'auto-refresh-toggle', 'real-time-toggle', 
        'tooltips-toggle', 'developer-toggle', 'api-toggle', 'debug-toggle'
    ];
    
    toggles.forEach(toggleId => {
        const toggle = document.getElementById(toggleId);
        if (toggle) {
            toggle.addEventListener('change', function() {
                // Visual feedback - update the toggle appearance
                const togglePill = this.nextElementSibling;
                if (this.checked) {
                    togglePill.classList.add('peer-checked:bg-primary/20');
                } else {
                    togglePill.classList.remove('peer-checked:bg-primary/20');
                }
                
                // Save the setting
                saveSettings(toggleId, this.checked);
                
                // Apply special handling for certain toggles
                handleSpecialToggle(toggleId, this.checked);
            });
        }
    });
}

// Handle special toggle switches that affect UI
function handleSpecialToggle(toggleId, isChecked) {
    switch(toggleId) {
        case 'animation-toggle':
            // Enable/disable animations
            const root = document.documentElement;
            if (!isChecked) {
                // Disable animations
                root.style.setProperty('--animation-duration', '0s');
                document.querySelectorAll('.animate-pulse').forEach(el => {
                    el.classList.remove('animate-pulse');
                });
            } else {
                // Enable animations
                root.style.setProperty('--animation-duration', '0.3s');
                // Re-enable pulse animations
                document.querySelectorAll('.neo-progress-bar').forEach(el => {
                    el.classList.add('animate-pulse');
                });
            }
            break;
            
        case 'density-toggle':
            // Toggle UI density
            const body = document.body;
            if (isChecked) {
                body.classList.add('ui-comfortable');
                body.classList.remove('ui-compact');
            } else {
                body.classList.add('ui-compact');
                body.classList.remove('ui-comfortable');
            }
            break;
            
        case 'auto-refresh-toggle':
            // Toggle data auto-refresh
            window.autoRefreshEnabled = isChecked;
            break;
            
        case 'real-time-toggle':
            // Toggle real-time monitoring
            window.realTimeEnabled = isChecked;
            break;
            
        case 'developer-toggle':
            // Toggle developer mode
            if (isChecked) {
                document.body.classList.add('developer-mode');
                // Show developer features
                document.querySelectorAll('.dev-feature').forEach(el => {
                    el.classList.remove('hidden');
                });
            } else {
                document.body.classList.remove('developer-mode');
                // Hide developer features
                document.querySelectorAll('.dev-feature').forEach(el => {
                    el.classList.add('hidden');
                });
            }
            break;
    }
}

// Initialize all range sliders
function initializeRangeSliders() {
    const sliders = [
        {id: 'scan-frequency', valueId: 'scan-frequency-value', suffix: ''},
        {id: 'suspicious-threshold', valueId: 'suspicious-threshold-value', suffix: '%'},
        {id: 'confidence-threshold', valueId: 'confidence-threshold-value', suffix: '%'},
        {id: 'refresh-interval', valueId: 'refresh-interval-value', suffix: 's'}
    ];
    
    sliders.forEach(slider => {
        const sliderEl = document.getElementById(slider.id);
        if (sliderEl) {
            sliderEl.addEventListener('input', function() {
                // Update display value
                const valueEl = document.getElementById(slider.valueId);
                if (valueEl) {
                    valueEl.textContent = `${this.value}${slider.suffix}`;
                }
                
                // Save the setting
                saveSettings(slider.id, this.value);
                
                // Apply special handling for certain sliders
                handleSpecialSlider(slider.id, this.value);
            });
        }
    });
}

// Handle sliders that affect UI or system behavior
function handleSpecialSlider(sliderId, value) {
    switch(sliderId) {
        case 'refresh-interval':
            // Update refresh interval
            window.dataRefreshInterval = parseInt(value) * 1000; // Convert to milliseconds
            break;
            
        case 'confidence-threshold':
            // Update confidence threshold
            window.confidenceThreshold = parseInt(value);
            break;
    }
}

// Initialize radio button groups
function initializeRadioButtons() {
    // Protection mode radio group
    const protectionModes = ['protection-normal', 'protection-aggressive', 'protection-learning'];
    
    protectionModes.forEach(radioId => {
        const radio = document.getElementById(radioId);
        if (radio) {
            radio.addEventListener('change', function() {
                if (this.checked) {
                    // Save the setting
                    saveSettings('protection-mode', radioId);
                    
                    // Show notification about mode change
                    let modeText = '';
                    if (radioId === 'protection-normal') modeText = 'Normal Protection';
                    else if (radioId === 'protection-aggressive') modeText = 'Aggressive Protection';
                    else if (radioId === 'protection-learning') modeText = 'Learning Mode';
                    
                    showNotification(`${modeText} enabled`, 'info');
                }
            });
        }
    });
}

// Save a single setting to localStorage
function saveSettings(key, value) {
    try {
        // Get existing settings or initialize empty object
        let settings = JSON.parse(localStorage.getItem('cybershield-settings') || '{}');
        
        // Update the specific setting
        settings[key] = value;
        
        // Save back to localStorage
        localStorage.setItem('cybershield-settings', JSON.stringify(settings));
        
        return true;
    } catch (error) {
        console.error('Error saving settings:', error);
        return false;
    }
}

// Save all current settings
function saveAllSettings() {
    // Collect all toggle states
    document.querySelectorAll('input[type="checkbox"]').forEach(toggle => {
        if (toggle.id) {
            saveSettings(toggle.id, toggle.checked);
        }
    });
    
    // Collect all range slider values
    document.querySelectorAll('input[type="range"]').forEach(slider => {
        if (slider.id) {
            saveSettings(slider.id, slider.value);
        }
    });
    
    // Collect radio button states
    const protectionMode = document.querySelector('input[name="protection-mode"]:checked');
    if (protectionMode) {
        saveSettings('protection-mode', protectionMode.id);
    }
    
    // Collect dropdown values
    const logLevel = document.getElementById('log-level');
    if (logLevel) {
        saveSettings('log-level', logLevel.value);
    }
    
    // Collect input field values
    const emailRecipient = document.getElementById('email-recipient');
    if (emailRecipient) {
        saveSettings('email-recipients', emailRecipient.value);
    }
    
    // Save current theme
    const selectedTheme = document.querySelector('.theme-option.selected');
    if (selectedTheme) {
        saveSettings('theme', selectedTheme.id);
    }
}

// Load saved settings from localStorage
function loadSavedSettings(themeAlreadyLoaded = true) {
    try {
        const settings = JSON.parse(localStorage.getItem('cybershield-settings') || '{}');
        
        // Apply each saved setting
        Object.keys(settings).forEach(key => {
            const value = settings[key];
            
            // Handle toggles
            if (key.includes('toggle')) {
                const toggle = document.getElementById(key);
                if (toggle) {
                    toggle.checked = value;
                    // Trigger change event to apply visual updates
                    const event = new Event('change');
                    toggle.dispatchEvent(event);
                }
            }
            
            // Handle range sliders
            else if (key.includes('threshold') || key.includes('frequency') || key.includes('interval')) {
                const slider = document.getElementById(key);
                if (slider) {
                    slider.value = value;
                    // Update displayed value
                    const valueDisplay = document.getElementById(`${key}-value`);
                    if (valueDisplay) {
                        if (key.includes('threshold')) {
                            valueDisplay.textContent = `${value}%`;
                        } else if (key.includes('interval')) {
                            valueDisplay.textContent = `${value}s`;
                        } else {
                            valueDisplay.textContent = value;
                        }
                    }
                }
            }
            
            // Handle radio buttons
            else if (key === 'protection-mode') {
                const radio = document.getElementById(value);
                if (radio) {
                    radio.checked = true;
                }
            }
            
            // Handle theme only if not already loaded separately
            else if (key === 'theme' && !themeAlreadyLoaded) {
                const theme = document.getElementById(value);
                if (theme) {
                    // Remove selected class from all themes
                    document.querySelectorAll('.theme-option').forEach(t => {
                        t.classList.remove('selected');
                        t.querySelector('.w-4.h-4').classList.remove('bg-primary');
                    });
                    
                    // Add selected class to saved theme
                    theme.classList.add('selected');
                    theme.querySelector('.w-4.h-4').classList.add('bg-primary');
                    
                    // Apply the theme
                    applyTheme(value);
                }
            }
            
            // Handle dropdown
            else if (key === 'log-level') {
                const dropdown = document.getElementById(key);
                if (dropdown) {
                    dropdown.value = value;
                }
            }
            
            // Handle input fields
            else if (key === 'email-recipients') {
                const input = document.getElementById('email-recipient');
                if (input) {
                    input.value = value;
                }
            }
        });
        
        return true;
    } catch (error) {
        console.error('Error loading settings:', error);
        return false;
    }
}

// Load only the theme setting from localStorage
function loadSavedTheme() {
    try {
        const settings = JSON.parse(localStorage.getItem('cybershield-settings') || '{}');
        
        // Only apply theme if it exists in settings
        if (settings.theme) {
            const theme = document.getElementById(settings.theme);
            if (theme) {
                // Remove selected class from all themes
                document.querySelectorAll('.theme-option').forEach(t => {
                    t.classList.remove('selected');
                    t.querySelector('.w-4.h-4').classList.remove('bg-primary');
                });
                
                // Add selected class to saved theme
                theme.classList.add('selected');
                theme.querySelector('.w-4.h-4').classList.add('bg-primary');
                
                // Apply the theme without showing notification
                applyTheme(settings.theme, false);
            }
        }
        
        return true;
    } catch (error) {
        console.error('Error loading theme:', error);
        return false;
    }
}

// Dynamic resource monitor for Infrastructure tab
function initResourceMonitor() {
    // Check if we're on the page with resource monitors
    if (!document.getElementById('cpu-percentage')) return;
    
    // Apply blinking effect to all resource values
    const blink = () => {
        document.querySelectorAll('.cpu-value, .memory-value, .disk-value').forEach(el => {
            el.style.opacity = Math.random() > 0.1 ? 1 : 0.7; // Occasional small blink
        });
    };
    
    setInterval(blink, 500); // Apply blinking effect
    
    // Function to update resource values with random fluctuations
    const updateResourceValues = () => {
        // CPU values
        let cpuPercentage = randomizeValue(42, 5);
        document.getElementById('cpu-percentage').textContent = `${cpuPercentage}%`;
        document.getElementById('cpu-indicator').style.width = `${cpuPercentage}%`;
        
        let core1Usage = randomizeValue(38, 4);
        document.getElementById('core1-usage').textContent = `${core1Usage}%`;
        document.getElementById('core1-bar').style.width = `${core1Usage}%`;
        
        let core2Usage = randomizeValue(45, 5);
        document.getElementById('core2-usage').textContent = `${core2Usage}%`;
        document.getElementById('core2-bar').style.width = `${core2Usage}%`;
        
        // Memory values
        let memoryPercentage = randomizeValue(68, 3);
        let totalMemory = 16;
        let usedMemory = (memoryPercentage * totalMemory / 100).toFixed(1);
        let availableMemory = (totalMemory - usedMemory).toFixed(1);
        
        document.getElementById('memory-percentage').textContent = `${memoryPercentage}%`;
        document.getElementById('memory-indicator').style.width = `${memoryPercentage}%`;
        document.getElementById('used-memory').textContent = `${usedMemory} GB`;
        document.getElementById('available-memory').textContent = `${availableMemory} GB`;
        
        // Disk values
        let diskPercentage = randomizeValue(55, 2);
        let totalDisk = 1000; // 1 TB in GB
        let usedDisk = Math.round(diskPercentage * totalDisk / 100);
        let availableDisk = totalDisk - usedDisk;
        
        document.getElementById('disk-percentage').textContent = `${diskPercentage}%`;
        document.getElementById('disk-indicator').style.width = `${diskPercentage}%`;
        document.getElementById('used-disk').textContent = `${usedDisk} GB`;
        document.getElementById('available-disk').textContent = `${availableDisk} GB`;
        
        // Add warning class if usage is too high
        updateWarningState('cpu-percentage', cpuPercentage, 80);
        updateWarningState('memory-percentage', memoryPercentage, 85);
        updateWarningState('disk-percentage', diskPercentage, 90);
    };
    
    // Helper function to add or remove warning state
    function updateWarningState(elementId, value, threshold) {
        const element = document.getElementById(elementId);
        if (value > threshold) {
            element.classList.add('text-warning');
            element.classList.remove('text-primary', 'text-tertiary', 'text-secondary');
            element.style.textShadow = '0 0 10px var(--warning)';
        } else {
            if (elementId === 'cpu-percentage') {
                element.classList.add('text-primary');
                element.style.textShadow = '0 0 10px var(--primary)';
            } else if (elementId === 'memory-percentage') {
                element.classList.add('text-tertiary');
                element.style.textShadow = '0 0 10px var(--tertiary)';
            } else if (elementId === 'disk-percentage') {
                element.classList.add('text-secondary');
                element.style.textShadow = '0 0 10px var(--secondary)';
            }
            element.classList.remove('text-warning');
        }
    }
    
    // Helper function to randomize values within a range
    function randomizeValue(baseValue, range) {
        return Math.max(0, Math.min(100, 
            Math.round(baseValue + (Math.random() * range * 2 - range))
        ));
    }
    
    // Update the values every 2 seconds
    setInterval(updateResourceValues, 2000);
    updateResourceValues(); // Initial update
}

// Apply theme changes
function applyTheme(themeId, showNotify = true) {
    const root = document.documentElement;
    
    // Reset to default theme
    root.style.setProperty('--primary', '#23C8FF');
    root.style.setProperty('--primary-dark', '#15A1D9');
    root.style.setProperty('--secondary', '#FFB629');
    root.style.setProperty('--tertiary', '#FF4081');
    root.style.setProperty('--success', '#1CEFAF');
    root.style.setProperty('--warning', '#F5C346');
    root.style.setProperty('--danger', '#FF5252');
    root.style.setProperty('--dark', '#111A2C');
    root.style.setProperty('--darker', '#0A0E1A');
    root.style.setProperty('--light-dark', '#1E293B');
    root.style.setProperty('--border', '#2B3A55');
    
    // Apply selected theme
    switch(themeId) {
        case 'theme-midnight':
            root.style.setProperty('--primary', '#7B42F6');
            root.style.setProperty('--primary-dark', '#6535D4');
            root.style.setProperty('--dark', '#0D1324');
            root.style.setProperty('--darker', '#030B16');
            root.style.setProperty('--light-dark', '#162039');
            root.style.setProperty('--border', '#253354');
            root.style.setProperty('--tertiary', '#FF3C7A');
            break;
        case 'theme-matrix':
            root.style.setProperty('--primary', '#00FF00');
            root.style.setProperty('--primary-dark', '#00CC00');
            root.style.setProperty('--dark', '#001800');
            root.style.setProperty('--darker', '#001100');
            root.style.setProperty('--light-dark', '#002200');
            root.style.setProperty('--border', '#003300');
            root.style.setProperty('--success', '#00FFAA');
            root.style.setProperty('--secondary', '#AAFF00');
            root.style.setProperty('--tertiary', '#00FFFF');
            break;
        case 'theme-crimson':
            root.style.setProperty('--primary', '#FF5252');
            root.style.setProperty('--primary-dark', '#D43535');
            root.style.setProperty('--dark', '#1A0D0D');
            root.style.setProperty('--darker', '#1A0505');
            root.style.setProperty('--light-dark', '#2B1616');
            root.style.setProperty('--border', '#3B2121');
            root.style.setProperty('--tertiary', '#FF9C3C');
            root.style.setProperty('--secondary', '#FF3C7A');
            break;
    }
    
    // Show a notification about theme change if requested
    if (showNotify) {
    showNotification('Theme applied', 'success');
    }
}

// Show notification
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `fixed bottom-4 right-4 p-4 rounded-lg shadow-lg z-50 ${
        type === 'success' ? 'bg-success/20 text-success border border-success/30' :
        type === 'warning' ? 'bg-warning/20 text-warning border border-warning/30' :
        type === 'error' ? 'bg-danger/20 text-danger border border-danger/30' :
        'bg-primary/20 text-primary border border-primary/30'
    }`;
    
    notification.innerHTML = `
        <div class="flex items-center gap-2">
            <i class="fas fa-${
                type === 'success' ? 'check-circle' :
                type === 'warning' ? 'exclamation-triangle' :
                type === 'error' ? 'times-circle' :
                'info-circle'
            }"></i>
            <span>${message}</span>
        </div>
    `;
    
    // Add to DOM
    document.body.appendChild(notification);
    
    // Remove after timeout
    setTimeout(() => {
        notification.classList.add('opacity-0');
        notification.style.transition = 'opacity 0.5s ease';
        setTimeout(() => {
            notification.remove();
        }, 500);
    }, 3000);
}

// Interactive Threat Map functionality
function initThreatMap() {
    const mapContainer = document.getElementById('world-map');
    if (!mapContainer) return;
    
    // Clear any existing content
    mapContainer.innerHTML = '';
    
    // Create SVG element for the world map
    const svgNS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("viewBox", "0 0 1000 500");
    svg.setAttribute("class", "w-full h-full");
    mapContainer.appendChild(svg);
    
    // Draw simplified world map (simplified country outlines)
    drawWorldMap(svg);
    
    // Add attack sources and paths
    addAttackSources(svg);
}

// Draw a simplified world map
function drawWorldMap(svg) {
    const svgNS = "http://www.w3.org/2000/svg";
    
    // Simplified world map path (this is a very basic representation)
    const continents = [
        { 
            name: "North America", 
            path: "M 170 120 C 180 110, 220 100, 250 120 C 270 130, 280 150, 290 180 C 300 210, 290 230, 280 250 C 270 270, 250 290, 220 300 C 200 310, 180 300, 160 280 C 140 260, 130 240, 120 210 C 110 180, 120 150, 140 130 C 150 120, 160 120, 170 120 Z", 
            color: "rgba(35, 200, 255, 0.2)" 
        },
        { 
            name: "South America", 
            path: "M 280 320 C 290 310, 300 310, 320 320 C 340 330, 350 350, 350 380 C 350 410, 340 440, 320 460 C 300 480, 270 480, 250 460 C 230 440, 220 410, 230 380 C 240 350, 260 330, 280 320 Z", 
            color: "rgba(35, 200, 255, 0.15)" 
        },
        { 
            name: "Europe", 
            path: "M 480 100 C 500 90, 530 90, 550 100 C 570 110, 580 130, 580 150 C 580 170, 570 190, 550 200 C 540 210, 520 220, 500 210 C 480 200, 460 190, 450 170 C 440 150, 450 120, 480 100 Z", 
            color: "rgba(35, 200, 255, 0.25)" 
        },
        { 
            name: "Africa", 
            path: "M 500 230 C 520 220, 550 220, 570 230 C 590 240, 600 260, 600 290 C 600 320, 590 350, 570 380 C 550 410, 530 420, 500 410 C 470 400, 450 380, 440 350 C 430 320, 440 280, 460 250 C 480 230, 500 230, 500 230 Z", 
            color: "rgba(35, 200, 255, 0.15)" 
        },
        { 
            name: "Asia", 
            path: "M 600 100 C 650 80, 700 90, 750 110 C 800 130, 820 170, 830 220 C 840 270, 820 320, 780 350 C 740 380, 700 380, 650 360 C 620 350, 600 330, 580 300 C 570 280, 580 260, 600 240 C 620 220, 630 200, 620 170 C 610 140, 600 120, 600 100 Z", 
            color: "rgba(35, 200, 255, 0.3)" 
        },
        { 
            name: "Australia", 
            path: "M 800 380 C 820 370, 840 370, 860 380 C 880 390, 890 410, 890 430 C 890 450, 880 470, 860 480 C 840 490, 820 490, 800 480 C 780 470, 770 450, 770 430 C 770 410, 780 390, 800 380 Z", 
            color: "rgba(35, 200, 255, 0.2)" 
        }
    ];
    
    // Add continents to the map
    for (const continent of continents) {
        const path = document.createElementNS(svgNS, "path");
        path.setAttribute("d", continent.path);
        path.setAttribute("fill", continent.color);
        path.setAttribute("stroke", "rgba(35, 200, 255, 0.5)");
        path.setAttribute("stroke-width", "1");
        path.setAttribute("data-continent", continent.name);
        
        // Add hover effect
        path.addEventListener("mouseenter", function() {
            this.setAttribute("fill", "rgba(35, 200, 255, 0.4)");
        });
        
        path.addEventListener("mouseleave", function() {
            this.setAttribute("fill", continent.color);
        });
        
        svg.appendChild(path);
    }
    
    // Add grid lines for a techy look
    const gridGroup = document.createElementNS(svgNS, "g");
    gridGroup.setAttribute("class", "grid-lines");
    
    // Horizontal grid lines
    for (let y = 50; y < 500; y += 50) {
        const line = document.createElementNS(svgNS, "line");
        line.setAttribute("x1", "0");
        line.setAttribute("y1", y);
        line.setAttribute("x2", "1000");
        line.setAttribute("y2", y);
        line.setAttribute("stroke", "rgba(35, 200, 255, 0.1)");
        line.setAttribute("stroke-width", "1");
        gridGroup.appendChild(line);
    }
    
    // Vertical grid lines
    for (let x = 50; x < 1000; x += 50) {
        const line = document.createElementNS(svgNS, "line");
        line.setAttribute("x1", x);
        line.setAttribute("y1", "0");
        line.setAttribute("x2", x);
        line.setAttribute("y2", "500");
        line.setAttribute("stroke", "rgba(35, 200, 255, 0.1)");
        line.setAttribute("stroke-width", "1");
        gridGroup.appendChild(line);
    }
    
    svg.appendChild(gridGroup);
}

// Sample attack origins data (this would normally come from your backend)
const attackOrigins = [
    { name: "Russia", coords: [650, 120], weight: 35 },
    { name: "China", coords: [750, 220], weight: 40 },
    { name: "United States", coords: [200, 180], weight: 25 },
    { name: "Brazil", coords: [300, 380], weight: 15 },
    { name: "Nigeria", coords: [500, 320], weight: 10 },
    { name: "Ukraine", coords: [550, 150], weight: 20 },
    { name: "South Korea", coords: [780, 200], weight: 12 },
    { name: "Germany", coords: [510, 140], weight: 18 },
    { name: "Australia", coords: [820, 430], weight: 8 }
];

// Sample target (your protected server)
const target = { coords: [520, 250] }; // Somewhere central on the map

// Add attack sources and attack paths to the map
function addAttackSources(svg) {
    const svgNS = "http://www.w3.org/2000/svg";
    
    // Create a group for attacks
    const attackGroup = document.createElementNS(svgNS, "g");
    attackGroup.setAttribute("class", "attack-vectors");
    
    // Create markers for animated attack paths
    const defs = document.createElementNS(svgNS, "defs");
    svg.appendChild(defs);
    
    const marker = document.createElementNS(svgNS, "marker");
    marker.setAttribute("id", "arrowhead");
    marker.setAttribute("markerWidth", "5");
    marker.setAttribute("markerHeight", "5");
    marker.setAttribute("refX", "5");
    marker.setAttribute("refY", "2.5");
    marker.setAttribute("orient", "auto");
    
    const polygon = document.createElementNS(svgNS, "polygon");
    polygon.setAttribute("points", "0 0, 5 2.5, 0 5");
    polygon.setAttribute("fill", "rgba(255, 82, 82, 0.8)");
    marker.appendChild(polygon);
    defs.appendChild(marker);
    
    // Add the protected target (your server)
    const targetCircle = document.createElementNS(svgNS, "circle");
    targetCircle.setAttribute("cx", target.coords[0]);
    targetCircle.setAttribute("cy", target.coords[1]);
    targetCircle.setAttribute("r", "8");
    targetCircle.setAttribute("fill", "rgba(28, 239, 175, 0.6)");
    targetCircle.setAttribute("stroke", "rgba(28, 239, 175, 0.8)");
    targetCircle.setAttribute("stroke-width", "2");
    
    // Pulsating animation for target
    const targetAnimation = document.createElementNS(svgNS, "animate");
    targetAnimation.setAttribute("attributeName", "r");
    targetAnimation.setAttribute("values", "8;12;8");
    targetAnimation.setAttribute("dur", "3s");
    targetAnimation.setAttribute("repeatCount", "indefinite");
    targetCircle.appendChild(targetAnimation);
    
    attackGroup.appendChild(targetCircle);
    
    // Add text label for target
    const targetLabel = document.createElementNS(svgNS, "text");
    targetLabel.setAttribute("x", target.coords[0] + 15);
    targetLabel.setAttribute("y", target.coords[1] - 10);
    targetLabel.setAttribute("fill", "rgba(28, 239, 175, 0.9)");
    targetLabel.setAttribute("font-size", "12");
    targetLabel.setAttribute("font-family", "IBM Plex Mono, monospace");
    targetLabel.textContent = "Protected Server";
    attackGroup.appendChild(targetLabel);
    
    // Add attack sources and animated paths
    attackOrigins.forEach((origin, index) => {
        // Attack source point
        const circle = document.createElementNS(svgNS, "circle");
        circle.setAttribute("cx", origin.coords[0]);
        circle.setAttribute("cy", origin.coords[1]);
        circle.setAttribute("r", 4 + (origin.weight / 10));
        circle.setAttribute("fill", "rgba(255, 82, 82, 0.6)");
        circle.setAttribute("stroke", "rgba(255, 82, 82, 0.8)");
        circle.setAttribute("stroke-width", "1");
        circle.setAttribute("class", "attack-source");
        circle.setAttribute("data-country", origin.name);
        
        // Add tooltip behavior
        circle.addEventListener("mouseenter", function() {
            const tooltip = document.createElementNS(svgNS, "text");
            tooltip.setAttribute("x", origin.coords[0] + 10);
            tooltip.setAttribute("y", origin.coords[1] - 5);
            tooltip.setAttribute("fill", "white");
            tooltip.setAttribute("font-size", "12");
            tooltip.setAttribute("font-family", "IBM Plex Mono, monospace");
            tooltip.setAttribute("id", `tooltip-${index}`);
            tooltip.textContent = `${origin.name}: ${origin.weight}%`;
            attackGroup.appendChild(tooltip);
            
            // Highlight the attack path
            document.getElementById(`attack-path-${index}`).setAttribute("stroke-opacity", "0.8");
            document.getElementById(`attack-path-${index}`).setAttribute("stroke-width", "2");
        });
        
        circle.addEventListener("mouseleave", function() {
            attackGroup.removeChild(document.getElementById(`tooltip-${index}`));
            document.getElementById(`attack-path-${index}`).setAttribute("stroke-opacity", "0.3");
            document.getElementById(`attack-path-${index}`).setAttribute("stroke-width", "1");
        });
        
        attackGroup.appendChild(circle);
        
        // Attack line from source to target
        const line = document.createElementNS(svgNS, "line");
        line.setAttribute("x1", origin.coords[0]);
        line.setAttribute("y1", origin.coords[1]);
        line.setAttribute("x2", target.coords[0]);
        line.setAttribute("y2", target.coords[1]);
        line.setAttribute("stroke", `rgba(255, 82, 82, ${origin.weight / 100 + 0.2})`);
        line.setAttribute("stroke-width", "1");
        line.setAttribute("stroke-opacity", "0.3");
        line.setAttribute("stroke-dasharray", "6,3");
        line.setAttribute("id", `attack-path-${index}`);
        line.setAttribute("marker-end", "url(#arrowhead)");
        attackGroup.appendChild(line);
        
        // Animated packet traveling along the attack path
        const animatePacket = () => {
            const packet = document.createElementNS(svgNS, "circle");
            packet.setAttribute("r", "3");
            packet.setAttribute("fill", "rgba(255, 82, 82, 0.8)");
            
            // Create a path for the packet to follow
            const path = document.createElementNS(svgNS, "path");
            path.setAttribute("d", `M${origin.coords[0]},${origin.coords[1]} L${target.coords[0]},${target.coords[1]}`);
            path.setAttribute("stroke", "none");
            path.setAttribute("id", `packet-path-${index}`);
            attackGroup.appendChild(path);
            
            // Animate the packet along the path
            const animateMotion = document.createElementNS(svgNS, "animateMotion");
            animateMotion.setAttribute("dur", `${3 + Math.random() * 2}s`);
            animateMotion.setAttribute("repeatCount", "1");
            animateMotion.setAttribute("path", `M0,0 L${target.coords[0] - origin.coords[0]},${target.coords[1] - origin.coords[1]}`);
            
            // Remove the packet when animation ends
            animateMotion.addEventListener("endEvent", function() {
                attackGroup.removeChild(packet);
                
                // Show attack indicator briefly
                const indicator = document.getElementById('attack-indicator');
                if (indicator) {
                    indicator.classList.remove('hidden');
                    setTimeout(() => {
                        indicator.classList.add('hidden');
                    }, 2000);
                }
            });
            
            packet.appendChild(animateMotion);
            attackGroup.appendChild(packet);
            
            // Start the animation
            animateMotion.beginElement();
        };
        
        // Start packet animation at random intervals based on attack weight
        setInterval(animatePacket, 10000 / origin.weight);
    });
    
    svg.appendChild(attackGroup);
}

// Refresh the threat map with new data
function refreshThreatMap() {
    // In a real application, this would fetch new data from the server
    // Here we'll just regenerate with slightly different values
    
    // Update attack weights randomly
    attackOrigins.forEach(origin => {
        origin.weight = Math.max(5, Math.min(50, 
            origin.weight + (Math.random() * 10 - 5)
        ));
    });
    
    // Re-initialize the map
    initThreatMap();
}

// Add tab change listeners
document.querySelectorAll('.neo-sidebar-link').forEach(link => {
    link.addEventListener('click', function() {
        // If switching to threat analysis tab, initialize the map
        if (this.getAttribute('data-tab') === 'threat-analysis') {
            setTimeout(initThreatMap, 100); // Small delay to ensure DOM is ready
        }
    });
});

// Listen for the refresh button click on threat map
document.getElementById('refresh-threat-map')?.addEventListener('click', function() {
    refreshThreatMap();
    showNotification('Threat map updated', 'info');
});

// Add initialization for detailed geographic map
document.addEventListener('DOMContentLoaded', function() {
    // Add event listener for threat analysis tab
    document.querySelector('.neo-sidebar-link[data-tab="threat-analysis"]')?.addEventListener('click', function() {
        setTimeout(function() {
            initDetailedWorldMap();
        }, 300);
    });
    
    // Initialize zoom controls for the map
    document.getElementById('zoom-in-map')?.addEventListener('click', function() {
        zoomMap(1.2);
    });
    
    document.getElementById('zoom-out-map')?.addEventListener('click', function() {
        zoomMap(0.8);
    });
    
    document.getElementById('reset-map-view')?.addEventListener('click', function() {
        resetMapZoom();
    });
});

// Current zoom level and map SVG reference
let mapZoomLevel = 1;
let geoMapSvg = null;

// Attack locations with real geographic data
const attackLocations = [
    { name: "Moscow, Russia", coords: [55.7558, 37.6173], attacks: 372, severity: "high" },
    { name: "Beijing, China", coords: [39.9042, 116.4074], attacks: 421, severity: "high" },
    { name: "New York, USA", coords: [40.7128, -74.0060], attacks: 254, severity: "medium" },
    { name: "Sao Paulo, Brazil", coords: [23.5505, -46.6333], attacks: 142, severity: "medium" },
    { name: "Lagos, Nigeria", coords: [6.5244, 3.3792], attacks: 87, severity: "low" },
    { name: "Kiev, Ukraine", coords: [50.4501, 30.5234], attacks: 219, severity: "medium" },
    { name: "Seoul, South Korea", coords: [37.5665, 126.9780], attacks: 127, severity: "medium" },
    { name: "Berlin, Germany", coords: [52.5200, 13.4050], attacks: 168, severity: "medium" },
    { name: "Sydney, Australia", coords: [-33.8688, 151.2093], attacks: 65, severity: "low" },
    { name: "Tehran, Iran", coords: [35.6892, 51.3890], attacks: 305, severity: "high" },
    { name: "Pyongyang, North Korea", coords: [39.0392, 125.7625], attacks: 311, severity: "high" },
    { name: "Bucharest, Romania", coords: [44.4268, 26.1025], attacks: 134, severity: "medium" },
    { name: "Singapore", coords: [1.3521, 103.8198], attacks: 91, severity: "low" },
    { name: "Mumbai, India", coords: [19.0760, 72.8777], attacks: 185, severity: "medium" },
    { name: "Johannesburg, South Africa", coords: [-26.2041, 28.0473], attacks: 76, severity: "low" }
];

// Target location (protected server)
const protectedServer = { name: "Protected Server", coords: [48.8566, 2.3522] }; // Paris as an example center point

// Initialize the detailed world map
function initDetailedWorldMap() {
    const container = document.getElementById('geo-world-map');
    if (!container) return;
    
    // Clear any existing content
    container.innerHTML = '';
    
    // Create SVG element for world map
    const svgNS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("viewBox", "0 0 1000 500");
    svg.setAttribute("class", "w-full h-full");
    svg.setAttribute("id", "geo-map-svg");
    container.appendChild(svg);
    
    // Store reference to SVG
    geoMapSvg = svg;
    
    // Draw world map
    drawGeoWorldMap(svg);
    
    // Add attack markers and paths
    addAttackMarkers(svg);
    
    // Update attack origins list
    updateAttackOriginsList();
}

// Draw a detailed world map with continents
function drawGeoWorldMap(svg) {
    const svgNS = "http://www.w3.org/2000/svg";
    
    // Define continent paths (simplified for SVG representation)
    const continents = [
        {
            name: "North America",
            path: "M 120 80 L 160 60 L 220 40 L 280 50 L 300 80 L 320 120 L 300 170 L 280 200 L 240 240 L 200 260 L 170 240 L 140 220 L 120 200 L 100 170 L 80 140 L 100 110 Z",
            color: "rgba(35, 200, 255, 0.15)"
        },
        {
            name: "South America",
            path: "M 240 280 L 260 270 L 280 280 L 300 300 L 320 340 L 300 400 L 280 440 L 260 460 L 240 450 L 220 430 L 210 400 L 220 350 Z",
            color: "rgba(35, 200, 255, 0.12)"
        },
        {
            name: "Europe",
            path: "M 420 80 L 460 60 L 500 70 L 520 90 L 540 120 L 520 140 L 500 160 L 480 170 L 460 160 L 440 150 L 420 130 L 410 110 Z",
            color: "rgba(35, 200, 255, 0.2)"
        },
        {
            name: "Africa",
            path: "M 450 180 L 480 170 L 520 180 L 550 210 L 570 250 L 560 300 L 540 350 L 510 380 L 480 360 L 450 330 L 430 290 L 440 230 Z",
            color: "rgba(35, 200, 255, 0.15)"
        },
        {
            name: "Asia",
            path: "M 540 70 L 580 50 L 650 40 L 720 60 L 780 90 L 820 130 L 840 180 L 830 230 L 800 280 L 750 300 L 700 320 L 650 310 L 600 280 L 570 240 L 540 200 L 520 170 L 540 130 Z",
            color: "rgba(35, 200, 255, 0.18)"
        },
        {
            name: "Australia",
            path: "M 800 320 L 830 310 L 860 330 L 880 360 L 870 390 L 840 410 L 810 400 L 790 380 L 780 350 Z",
            color: "rgba(35, 200, 255, 0.12)"
        }
    ];
    
    // Draw grid lines for a techy look
    const gridGroup = document.createElementNS(svgNS, "g");
    gridGroup.setAttribute("class", "geo-grid-lines");
    
    // Horizontal grid lines
    for (let y = 0; y < 500; y += 25) {
        const line = document.createElementNS(svgNS, "line");
        line.setAttribute("x1", "0");
        line.setAttribute("y1", y);
        line.setAttribute("x2", "1000");
        line.setAttribute("y2", y);
        line.setAttribute("stroke", "rgba(35, 200, 255, 0.05)");
        line.setAttribute("stroke-width", "1");
        gridGroup.appendChild(line);
    }
    
    // Vertical grid lines
    for (let x = 0; x < 1000; x += 25) {
        const line = document.createElementNS(svgNS, "line");
        line.setAttribute("x1", x);
        line.setAttribute("y1", "0");
        line.setAttribute("x2", x);
        line.setAttribute("y2", "500");
        line.setAttribute("stroke", "rgba(35, 200, 255, 0.05)");
        line.setAttribute("stroke-width", "1");
        gridGroup.appendChild(line);
    }
    
    svg.appendChild(gridGroup);
    
    // Create a group for continents
    const continentGroup = document.createElementNS(svgNS, "g");
    continentGroup.setAttribute("class", "geo-continents");
    continentGroup.setAttribute("id", "geo-continents");
    
    // Add continents
    for (const continent of continents) {
        const path = document.createElementNS(svgNS, "path");
        path.setAttribute("d", continent.path);
        path.setAttribute("fill", continent.color);
        path.setAttribute("stroke", "rgba(35, 200, 255, 0.4)");
        path.setAttribute("stroke-width", "1");
        path.setAttribute("data-name", continent.name);
        
        // Add hover effect
        path.addEventListener("mouseenter", function() {
            this.setAttribute("fill", "rgba(35, 200, 255, 0.3)");
            // Show continent name
            const tooltip = document.createElementNS(svgNS, "text");
            tooltip.setAttribute("id", "continent-tooltip");
            tooltip.setAttribute("x", "20");
            tooltip.setAttribute("y", "30");
            tooltip.setAttribute("fill", "white");
            tooltip.setAttribute("font-size", "14");
            tooltip.setAttribute("font-family", "IBM Plex Mono, monospace");
            tooltip.textContent = continent.name;
            svg.appendChild(tooltip);
        });
        
        path.addEventListener("mouseleave", function() {
            this.setAttribute("fill", continent.color);
            // Remove tooltip
            const tooltip = document.getElementById("continent-tooltip");
            if (tooltip) svg.removeChild(tooltip);
        });
        
        continentGroup.appendChild(path);
    }
    
    svg.appendChild(continentGroup);
    
    // Add country borders (simplified)
    const borderGroup = document.createElementNS(svgNS, "g");
    borderGroup.setAttribute("class", "geo-borders");
    
    // Major country borders (simplified paths)
    const borders = [
        "M 120 120 L 280 120", // US-Canada border
        "M 240 240 L 320 180", // US-Mexico border
        "M 460 120 L 520 120", // Western European borders
        "M 540 140 L 600 140", // Eastern European borders
        "M 650 180 L 700 180", // Central Asian borders
        "M 700 250 L 780 250", // East Asian borders
    ];
    
    for (const border of borders) {
        const path = document.createElementNS(svgNS, "path");
        path.setAttribute("d", border);
        path.setAttribute("fill", "none");
        path.setAttribute("stroke", "rgba(255, 255, 255, 0.2)");
        path.setAttribute("stroke-width", "0.5");
        path.setAttribute("stroke-dasharray", "2,2");
        borderGroup.appendChild(path);
    }
    
    svg.appendChild(borderGroup);
    
    // Add latitude/longitude reference lines
    const latLongGroup = document.createElementNS(svgNS, "g");
    latLongGroup.setAttribute("class", "geo-lat-long");
    
    // Equator
    const equator = document.createElementNS(svgNS, "line");
    equator.setAttribute("x1", "0");
    equator.setAttribute("y1", "250");
    equator.setAttribute("x2", "1000");
    equator.setAttribute("y2", "250");
    equator.setAttribute("stroke", "rgba(35, 200, 255, 0.3)");
    equator.setAttribute("stroke-width", "1");
    equator.setAttribute("stroke-dasharray", "5,3");
    latLongGroup.appendChild(equator);
    
    // Prime Meridian (approximate)
    const meridian = document.createElementNS(svgNS, "line");
    meridian.setAttribute("x1", "500");
    meridian.setAttribute("y1", "0");
    meridian.setAttribute("x2", "500");
    meridian.setAttribute("y2", "500");
    meridian.setAttribute("stroke", "rgba(35, 200, 255, 0.3)");
    meridian.setAttribute("stroke-width", "1");
    meridian.setAttribute("stroke-dasharray", "5,3");
    latLongGroup.appendChild(meridian);
    
    svg.appendChild(latLongGroup);
}

// Convert longitude and latitude to SVG coordinates
function coordsToSVG(lon, lat) {
    // Map longitude (-180 to 180) to SVG x (0 to 1000)
    const x = ((lon + 180) / 360) * 1000;
    
    // Map latitude (90 to -90) to SVG y (0 to 500)
    const y = ((90 - lat) / 180) * 500;
    
    return [x, y];
}

// Add attack markers to the map
function addAttackMarkers(svg) {
    const svgNS = "http://www.w3.org/2000/svg";
    
    // Create markers group
    const markersGroup = document.createElementNS(svgNS, "g");
    markersGroup.setAttribute("class", "geo-markers");
    markersGroup.setAttribute("id", "geo-markers");
    
    // Create defs for markers and animations
    const defs = document.createElementNS(svgNS, "defs");
    svg.appendChild(defs);
    
    // Create marker for attack paths
    const marker = document.createElementNS(svgNS, "marker");
    marker.setAttribute("id", "geo-arrowhead");
    marker.setAttribute("markerWidth", "5");
    marker.setAttribute("markerHeight", "5");
    marker.setAttribute("refX", "5");
    marker.setAttribute("refY", "2.5");
    marker.setAttribute("orient", "auto");
    
    const polygon = document.createElementNS(svgNS, "polygon");
    polygon.setAttribute("points", "0 0, 5 2.5, 0 5");
    polygon.setAttribute("fill", "rgba(255, 82, 82, 0.8)");
    marker.appendChild(polygon);
    defs.appendChild(marker);
    
    // Add protected server marker (target)
    const [targetX, targetY] = coordsToSVG(protectedServer.coords[1], protectedServer.coords[0]);
    
    const targetCircle = document.createElementNS(svgNS, "circle");
    targetCircle.setAttribute("cx", targetX);
    targetCircle.setAttribute("cy", targetY);
    targetCircle.setAttribute("r", "8");
    targetCircle.setAttribute("fill", "rgba(28, 239, 175, 0.6)");
    targetCircle.setAttribute("stroke", "rgba(28, 239, 175, 0.8)");
    targetCircle.setAttribute("stroke-width", "2");
    targetCircle.setAttribute("class", "protected-server");
    
    // Add pulse animation
    const animate = document.createElementNS(svgNS, "animate");
    animate.setAttribute("attributeName", "r");
    animate.setAttribute("values", "8;12;8");
    animate.setAttribute("dur", "3s");
    animate.setAttribute("repeatCount", "indefinite");
    targetCircle.appendChild(animate);
    
    markersGroup.appendChild(targetCircle);
    
    // Add target label
    const targetLabel = document.createElementNS(svgNS, "text");
    targetLabel.setAttribute("x", targetX + 15);
    targetLabel.setAttribute("y", targetY - 10);
    targetLabel.setAttribute("fill", "rgba(28, 239, 175, 0.9)");
    targetLabel.setAttribute("font-size", "12");
    targetLabel.setAttribute("font-family", "IBM Plex Mono, monospace");
    targetLabel.textContent = protectedServer.name;
    markersGroup.appendChild(targetLabel);
    
    // Add attack source markers with paths to target
    attackLocations.forEach((location, index) => {
        const [x, y] = coordsToSVG(location.coords[1], location.coords[0]);
        
        // Choose color based on severity
        let markerColor;
        if (location.severity === "high") {
            markerColor = "rgba(255, 82, 82, 0.8)"; // Red
        } else if (location.severity === "medium") {
            markerColor = "rgba(255, 182, 41, 0.8)"; // Yellow
        } else {
            markerColor = "rgba(28, 239, 175, 0.8)"; // Green
        }
        
        // Calculate marker radius based on attack count
        const radius = 3 + (location.attacks / 100);
        
        // Create attack source marker
        const circle = document.createElementNS(svgNS, "circle");
        circle.setAttribute("cx", x);
        circle.setAttribute("cy", y);
        circle.setAttribute("r", radius);
        circle.setAttribute("fill", markerColor);
        circle.setAttribute("stroke", markerColor.replace("0.8", "1"));
        circle.setAttribute("stroke-width", "1");
        circle.setAttribute("class", "attack-location");
        circle.setAttribute("data-location", location.name);
        circle.setAttribute("data-attacks", location.attacks);
        
        // Add hover behavior
        circle.addEventListener("mouseenter", function() {
            this.setAttribute("r", radius * 1.5);
            
            // Show tooltip
            const tooltip = document.createElementNS(svgNS, "g");
            tooltip.setAttribute("id", `geo-tooltip-${index}`);
            
            const tooltipBg = document.createElementNS(svgNS, "rect");
            tooltipBg.setAttribute("x", x + 10);
            tooltipBg.setAttribute("y", y - 35);
            tooltipBg.setAttribute("width", "150");
            tooltipBg.setAttribute("height", "30");
            tooltipBg.setAttribute("fill", "rgba(10, 14, 26, 0.8)");
            tooltipBg.setAttribute("stroke", markerColor);
            tooltipBg.setAttribute("stroke-width", "1");
            tooltipBg.setAttribute("rx", "3");
            tooltip.appendChild(tooltipBg);
            
            const tooltipText1 = document.createElementNS(svgNS, "text");
            tooltipText1.setAttribute("x", x + 15);
            tooltipText1.setAttribute("y", y - 20);
            tooltipText1.setAttribute("fill", "white");
            tooltipText1.setAttribute("font-size", "10");
            tooltipText1.setAttribute("font-family", "IBM Plex Mono, monospace");
            tooltipText1.textContent = location.name;
            tooltip.appendChild(tooltipText1);
            
            const tooltipText2 = document.createElementNS(svgNS, "text");
            tooltipText2.setAttribute("x", x + 15);
            tooltipText2.setAttribute("y", y - 8);
            tooltipText2.setAttribute("fill", markerColor);
            tooltipText2.setAttribute("font-size", "10");
            tooltipText2.setAttribute("font-family", "IBM Plex Mono, monospace");
            tooltipText2.textContent = `Attacks: ${location.attacks}`;
            tooltip.appendChild(tooltipText2);
            
            markersGroup.appendChild(tooltip);
            
            // Highlight path
            document.getElementById(`geo-path-${index}`).setAttribute("stroke-opacity", "0.8");
            document.getElementById(`geo-path-${index}`).setAttribute("stroke-width", "1.5");
        });
        
        circle.addEventListener("mouseleave", function() {
            this.setAttribute("r", radius);
            
            // Remove tooltip
            const tooltip = document.getElementById(`geo-tooltip-${index}`);
            if (tooltip) markersGroup.removeChild(tooltip);
            
            // Unhighlight path
            document.getElementById(`geo-path-${index}`).setAttribute("stroke-opacity", "0.4");
            document.getElementById(`geo-path-${index}`).setAttribute("stroke-width", "1");
        });
        
        markersGroup.appendChild(circle);
        
        // Add attack path
        const path = document.createElementNS(svgNS, "path");
        
        // Create curved path for better visualization
        const dx = targetX - x;
        const dy = targetY - y;
        const distance = Math.sqrt(dx * dx + dy * dy);
        const curvature = distance / 4; // Adjust curvature based on distance
        
        // Calculate control point for the curve
        const controlX = (x + targetX) / 2 - dy / 8;
        const controlY = (y + targetY) / 2 + dx / 8;
        
        // Define curved path
        const pathDef = `M ${x} ${y} Q ${controlX} ${controlY} ${targetX} ${targetY}`;
        
        path.setAttribute("d", pathDef);
        path.setAttribute("fill", "none");
        path.setAttribute("stroke", markerColor);
        path.setAttribute("stroke-width", "1");
        path.setAttribute("stroke-opacity", "0.4");
        path.setAttribute("stroke-dasharray", "4,2");
        path.setAttribute("marker-end", "url(#geo-arrowhead)");
        path.setAttribute("id", `geo-path-${index}`);
        
        markersGroup.appendChild(path);
        
        // Add animated packet traveling along the path
        setInterval(() => {
            if (Math.random() > 0.7) { // Only animate some paths randomly
                createPacketAnimation(markersGroup, x, y, targetX, targetY, controlX, controlY, markerColor);
            }
        }, 5000);
    });
    
    svg.appendChild(markersGroup);
}

// Create packet animation along attack path
function createPacketAnimation(group, startX, startY, endX, endY, controlX, controlY, color) {
    const svgNS = "http://www.w3.org/2000/svg";
    
    // Create packet
    const packet = document.createElementNS(svgNS, "circle");
    packet.setAttribute("r", "3");
    packet.setAttribute("fill", color);
    packet.setAttribute("class", "attack-packet");
    
    // Create path for animation
    const pathId = `packet-path-${Date.now()}`;
    const animPath = document.createElementNS(svgNS, "path");
    animPath.setAttribute("id", pathId);
    animPath.setAttribute("d", `M ${startX} ${startY} Q ${controlX} ${controlY} ${endX} ${endY}`);
    animPath.setAttribute("fill", "none");
    animPath.setAttribute("stroke", "none");
    group.appendChild(animPath);
    
    // Create animation
    const animateMotion = document.createElementNS(svgNS, "animateMotion");
    animateMotion.setAttribute("dur", `${2 + Math.random() * 2}s`);
    animateMotion.setAttribute("repeatCount", "1");
    animateMotion.setAttribute("path", `M 0 0 Q ${controlX-startX} ${controlY-startY} ${endX-startX} ${endY-startY}`);
    
    // Remove elements when animation ends
    animateMotion.addEventListener("endEvent", function() {
        group.removeChild(packet);
        group.removeChild(document.getElementById(pathId));
        
        // Show attack indicator briefly
        const indicator = document.getElementById('attack-indicator');
        if (indicator) {
            indicator.classList.remove('hidden');
            setTimeout(() => {
                indicator.classList.add('hidden');
            }, 1000);
        }
    });
    
    packet.appendChild(animateMotion);
    group.appendChild(packet);
    
    // Start animation
    animateMotion.beginElement();
}

// Update the attack origins list in the sidebar
function updateAttackOriginsList() {
    const list = document.getElementById('attack-origins-list');
    if (!list) return;
    
    // Clear existing items
    list.innerHTML = '';
    
    // Sort locations by attack count
    const sortedLocations = [...attackLocations].sort((a, b) => b.attacks - a.attacks);
    
    // Add top 5 locations to the list
    sortedLocations.slice(0, 5).forEach(location => {
        const item = document.createElement('div');
        item.className = 'flex items-center justify-between';
        
        // Set color based on severity
        let severityColor;
        if (location.severity === "high") {
            severityColor = "text-red-500";
        } else if (location.severity === "medium") {
            severityColor = "text-yellow-500";
        } else {
            severityColor = "text-green-500";
        }
        
        item.innerHTML = `
            <span class="font-mono">${location.name}</span>
            <span class="font-mono ${severityColor}">${location.attacks}</span>
        `;
        
        list.appendChild(item);
    });
}

// Zoom map in or out
function zoomMap(factor) {
    if (!geoMapSvg) return;
    
    // Update zoom level
    mapZoomLevel *= factor;
    
    // Limit zoom range
    mapZoomLevel = Math.max(0.5, Math.min(3, mapZoomLevel));
    
    // Apply zoom transform
    const continents = document.getElementById('geo-continents');
    const markers = document.getElementById('geo-markers');
    
    if (continents) {
        continents.setAttribute('transform', `scale(${mapZoomLevel}) translate(${(1-mapZoomLevel)*500/mapZoomLevel}, ${(1-mapZoomLevel)*250/mapZoomLevel})`);
    }
    
    if (markers) {
        markers.setAttribute('transform', `scale(${mapZoomLevel}) translate(${(1-mapZoomLevel)*500/mapZoomLevel}, ${(1-mapZoomLevel)*250/mapZoomLevel})`);
    }
}

// Reset map zoom
function resetMapZoom() {
    mapZoomLevel = 1;
    
    const continents = document.getElementById('geo-continents');
    const markers = document.getElementById('geo-markers');
    
    if (continents) {
        continents.setAttribute('transform', '');
    }
    
    if (markers) {
        markers.setAttribute('transform', '');
    }
} 