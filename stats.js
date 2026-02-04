console.log('stats.js loaded');

document.addEventListener('DOMContentLoaded', function() {
    // State
    var currentType = 'country';
    var currentRange = '24h';
    var currentService = 'all';
    var currentSort = { field: 'count', direction: 'desc' };
    var allItems = [];
    var selectedItems = new Set();
    var detailChart = null;

    // Chart colors (same as app.js)
    var chartColors = [
        'rgba(255, 99, 132, 0.8)',   // Red
        'rgba(54, 162, 235, 0.8)',   // Blue
        'rgba(255, 206, 86, 0.8)',   // Yellow
        'rgba(75, 192, 192, 0.8)',   // Teal
        'rgba(153, 102, 255, 0.8)',  // Purple
        'rgba(255, 159, 64, 0.8)',   // Orange
        'rgba(199, 199, 199, 0.8)',  // Gray
        'rgba(83, 102, 255, 0.8)',   // Indigo
        'rgba(255, 99, 255, 0.8)',   // Pink
        'rgba(99, 255, 132, 0.8)'    // Green
    ];

    // DOM elements
    var tableBody = document.getElementById('stats-table-body');
    var detailPlaceholder = document.getElementById('detail-placeholder');
    var detailContent = document.getElementById('detail-content');
    var detailTitle = document.getElementById('detail-title');
    var detailStats = document.getElementById('detail-stats');
    var compareBar = document.getElementById('compare-bar');
    var compareCount = document.getElementById('compare-count');
    var compareBtn = document.getElementById('compare-btn');
    var clearSelectionBtn = document.getElementById('clear-selection-btn');

    // Initialize detail chart
    function initDetailChart() {
        var ctx = document.getElementById('detail-chart').getContext('2d');
        detailChart = new Chart(ctx, {
            type: 'line',
            data: { labels: [], datasets: [] },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#ccc',
                            font: { size: 11 },
                            boxWidth: 12,
                            padding: 10
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#888', font: { size: 10 } },
                        grid: { color: 'rgba(255,255,255,0.1)' }
                    },
                    y: {
                        ticks: { color: '#888', font: { size: 10 } },
                        grid: { color: 'rgba(255,255,255,0.1)' }
                    }
                }
            }
        });
    }

    // Format numbers with commas for readability
    function formatCount(count) {
        return count.toLocaleString();
    }

    // Get service name from protocol and port (mirrors backend logic)
    function getServiceName(protocol, port) {
        if (protocol === 'TCP') {
            switch (port) {
                case 80: case 8080: return 'HTTP';
                case 443: case 8443: return 'HTTPS';
                case 22: return 'SSH';
                case 21: return 'FTP';
                case 20: return 'FTP-Data';
                case 25: case 587: return 'SMTP';
                case 110: return 'POP3';
                case 143: return 'IMAP';
                case 993: return 'IMAPS';
                case 995: return 'POP3S';
                case 23: return 'Telnet';
                case 3389: return 'RDP';
                case 5900: case 5901: return 'VNC';
                case 3306: return 'MySQL';
                case 5432: return 'PostgreSQL';
                case 27017: return 'MongoDB';
                case 6379: return 'Redis';
                case 11211: return 'Memcached';
                case 445: return 'SMB';
                case 139: return 'NetBIOS';
                case 1433: return 'MSSQL';
                case 1521: return 'Oracle';
                case 6667: case 6697: return 'IRC';
            }
        } else if (protocol === 'UDP') {
            switch (port) {
                case 53: return 'DNS';
                case 123: return 'NTP';
                case 161: case 162: return 'SNMP';
                case 67: case 68: return 'DHCP';
                case 69: return 'TFTP';
                case 514: return 'Syslog';
                case 1900: return 'SSDP';
                case 5353: return 'mDNS';
                case 51820: return 'WireGuard';
                case 500: case 4500: return 'IPSec';
                case 1194: return 'OpenVPN';
            }
        }
        return 'Other';
    }

    // Load available services for the current time range
    function loadServices() {
        fetch('/api/stats/services?range=' + currentRange)
            .then(function(response) { return response.json(); })
            .then(function(data) {
                var select = document.getElementById('serviceFilter');
                var currentValue = select.value;

                // Clear and rebuild options
                select.innerHTML = '';

                // Always add "All" option first
                var allOption = document.createElement('option');
                allOption.value = 'all';
                allOption.textContent = 'All';
                select.appendChild(allOption);

                // Add option for each service from DB
                data.forEach(function(item) {
                    var option = document.createElement('option');
                    option.value = item.name;
                    option.textContent = item.name + ' (' + item.count.toLocaleString() + ')';
                    select.appendChild(option);
                });

                // Restore selection if it still exists, otherwise reset to 'all'
                if (currentValue && select.querySelector('option[value="' + currentValue + '"]')) {
                    select.value = currentValue;
                } else {
                    select.value = 'all';
                    currentService = 'all';
                }
            })
            .catch(function(err) {
                console.error('Failed to load services:', err);
            });
    }

    // Handle service filter change
    function setupServiceFilter() {
        var select = document.getElementById('serviceFilter');
        select.addEventListener('change', function() {
            currentService = select.value;
            loadFullRankings();
            // Clear detail panel
            detailPlaceholder.style.display = 'block';
            detailContent.style.display = 'none';
        });
    }

    // Load full rankings
    function loadFullRankings() {
        tableBody.innerHTML = '<tr><td colspan="3">Loading...</td></tr>';

        fetch('/api/stats/top?type=' + currentType + '&range=' + currentRange + '&service=' + currentService + '&limit=100')
            .then(function(response) { return response.json(); })
            .then(function(data) {
                allItems = data.items || [];
                renderTable();
            })
            .catch(function(err) {
                console.error('Failed to load rankings:', err);
                tableBody.innerHTML = '<tr><td colspan="3">Error loading data</td></tr>';
            });
    }

    // Sort items
    function sortItems(items) {
        return items.slice().sort(function(a, b) {
            var aVal = a[currentSort.field];
            var bVal = b[currentSort.field];

            if (currentSort.field === 'name') {
                aVal = (aVal || '').toLowerCase();
                bVal = (bVal || '').toLowerCase();
                if (aVal < bVal) return currentSort.direction === 'asc' ? -1 : 1;
                if (aVal > bVal) return currentSort.direction === 'asc' ? 1 : -1;
                return 0;
            } else {
                aVal = aVal || 0;
                bVal = bVal || 0;
                return currentSort.direction === 'asc' ? aVal - bVal : bVal - aVal;
            }
        });
    }

    // Render table
    function renderTable() {
        if (allItems.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="3">No data available</td></tr>';
            return;
        }

        var sortedItems = sortItems(allItems);
        var html = '';

        sortedItems.forEach(function(item) {
            var isSelected = selectedItems.has(item.name);
            html += '<tr class="' + (isSelected ? 'selected' : '') + '" data-name="' + escapeHtml(item.name) + '">' +
                '<td class="col-checkbox"><input type="checkbox" ' + (isSelected ? 'checked' : '') + '></td>' +
                '<td class="col-name">' + escapeHtml(item.name || 'Unknown') + '</td>' +
                '<td class="col-count">' + formatCount(item.count) + '</td>' +
                '</tr>';
        });

        tableBody.innerHTML = html;

        // Add click handlers
        var rows = tableBody.querySelectorAll('tr');
        rows.forEach(function(row) {
            var checkbox = row.querySelector('input[type="checkbox"]');
            var name = row.dataset.name;

            // Row click - load drill-down
            row.addEventListener('click', function(e) {
                if (e.target.type !== 'checkbox') {
                    loadDrillDown(name);
                }
            });

            // Checkbox click - toggle selection
            if (checkbox) {
                checkbox.addEventListener('click', function(e) {
                    e.stopPropagation();
                    toggleSelection(name, checkbox.checked);
                });
            }
        });
    }

    // Toggle item selection
    function toggleSelection(name, selected) {
        if (selected) {
            selectedItems.add(name);
        } else {
            selectedItems.delete(name);
        }
        updateCompareBar();
        renderTable();
    }

    // Update compare bar visibility
    function updateCompareBar() {
        var count = selectedItems.size;
        compareCount.textContent = count;
        compareBar.style.display = count > 0 ? 'flex' : 'none';
    }

    // Clear all selections
    function clearSelections() {
        selectedItems.clear();
        updateCompareBar();
        renderTable();
    }

    // Load drill-down data for single item
    function loadDrillDown(name) {
        detailTitle.textContent = name;
        detailPlaceholder.style.display = 'none';
        detailContent.style.display = 'block';

        fetch('/api/stats/timeseries?type=' + currentType + '&range=' + currentRange + '&service=' + currentService + '&name=' + encodeURIComponent(name))
            .then(function(response) { return response.json(); })
            .then(function(data) {
                renderSingleChart(name, data);
                renderDetailStats(name, data);
            })
            .catch(function(err) {
                console.error('Failed to load timeseries:', err);
                detailStats.innerHTML = '<p>Error loading data</p>';
            });
    }

    // Load comparison data for multiple items
    function loadComparison() {
        var names = Array.from(selectedItems);
        if (names.length === 0) return;

        detailTitle.textContent = 'Comparison (' + names.length + ' items)';
        detailPlaceholder.style.display = 'none';
        detailContent.style.display = 'block';

        var promises = names.map(function(name) {
            return fetch('/api/stats/timeseries?type=' + currentType + '&range=' + currentRange + '&service=' + currentService + '&name=' + encodeURIComponent(name))
                .then(function(response) { return response.json(); });
        });

        Promise.all(promises).then(function(results) {
            renderComparisonChart(names, results);
            renderComparisonStats(names, results);
        }).catch(function(err) {
            console.error('Failed to load comparison:', err);
            detailStats.innerHTML = '<p>Error loading comparison data</p>';
        });
    }

    // Render single item chart
    function renderSingleChart(name, data) {
        var points = data.points || [];
        var labels = points.map(function(p) {
            return formatTimestamp(p.timestamp);
        });
        var values = points.map(function(p) { return p.count; });

        detailChart.data.labels = labels;
        detailChart.data.datasets = [{
            label: name,
            data: values,
            borderColor: chartColors[0],
            backgroundColor: chartColors[0].replace('0.8', '0.2'),
            borderWidth: 2,
            pointRadius: 2,
            tension: 0.3,
            fill: true
        }];
        detailChart.update();
    }

    // Render comparison chart
    function renderComparisonChart(names, results) {
        // Collect all unique timestamps
        var allTimestamps = new Set();
        results.forEach(function(result) {
            if (result.points) {
                result.points.forEach(function(p) { allTimestamps.add(p.timestamp); });
            }
        });

        var sortedTimestamps = Array.from(allTimestamps).sort(function(a, b) { return a - b; });
        var labels = sortedTimestamps.map(formatTimestamp);

        var datasets = results.map(function(result, index) {
            var dataMap = {};
            if (result.points) {
                result.points.forEach(function(p) { dataMap[p.timestamp] = p.count; });
            }

            var values = sortedTimestamps.map(function(ts) { return dataMap[ts] || 0; });
            var color = chartColors[index % chartColors.length];

            return {
                label: names[index],
                data: values,
                borderColor: color,
                backgroundColor: color.replace('0.8', '0.2'),
                borderWidth: 2,
                pointRadius: 0,
                tension: 0.3,
                fill: false
            };
        });

        detailChart.data.labels = labels;
        detailChart.data.datasets = datasets;
        detailChart.update();
    }

    // Format timestamp for chart labels
    function formatTimestamp(ts) {
        var date = new Date(ts * 1000);
        if (currentRange === '1h' || currentRange === '12h' || currentRange === '24h') {
            return date.getHours() + ':' + String(date.getMinutes()).padStart(2, '0');
        } else {
            return (date.getMonth() + 1) + '/' + date.getDate();
        }
    }

    // Render detail stats for single item
    function renderDetailStats(name, data) {
        var points = data.points || [];
        if (points.length === 0) {
            detailStats.innerHTML = '<p>No data available</p>';
            return;
        }

        var total = points.reduce(function(sum, p) { return sum + p.count; }, 0);
        var peak = points.reduce(function(max, p) { return p.count > max.count ? p : max; }, points[0]);
        var peakDate = new Date(peak.timestamp * 1000);
        var peakFormatted = peakDate.toLocaleDateString() + ' ' + peakDate.getHours() + ':00';

        detailStats.innerHTML =
            '<div class="stat-box">' +
                '<span class="stat-label">Total</span>' +
                '<span class="stat-value">' + formatCount(total) + ' packets</span>' +
            '</div>' +
            '<div class="stat-box">' +
                '<span class="stat-label">Peak</span>' +
                '<span class="stat-value">' + peakFormatted + '</span>' +
            '</div>' +
            '<div class="stat-box">' +
                '<span class="stat-label">Peak Count</span>' +
                '<span class="stat-value">' + formatCount(peak.count) + '</span>' +
            '</div>';
    }

    // Render comparison stats
    function renderComparisonStats(names, results) {
        var html = '';

        results.forEach(function(result, index) {
            var points = result.points || [];
            var total = points.reduce(function(sum, p) { return sum + p.count; }, 0);
            var color = chartColors[index % chartColors.length];

            html += '<div class="comparison-item" style="border-left: 3px solid ' + color + '">' +
                '<span class="comparison-name">' + escapeHtml(names[index]) + '</span>' +
                '<span class="comparison-value">' + formatCount(total) + '</span>' +
            '</div>';
        });

        detailStats.innerHTML = html;
    }

    // Escape HTML
    function escapeHtml(str) {
        if (!str) return '';
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // Update sort indicator
    function updateSortIndicator() {
        var headers = document.querySelectorAll('.stats-table th.sortable');
        headers.forEach(function(th) {
            th.classList.remove('active', 'asc', 'desc');
            if (th.dataset.sort === currentSort.field) {
                th.classList.add('active', currentSort.direction);
            }
        });
    }

    // Event handlers for time buttons
    document.querySelectorAll('.time-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            document.querySelectorAll('.time-btn').forEach(function(b) { b.classList.remove('active'); });
            btn.classList.add('active');
            currentRange = btn.dataset.range;
            loadServices();
            loadFullRankings();
            // Clear detail panel
            detailPlaceholder.style.display = 'block';
            detailContent.style.display = 'none';
        });
    });

    // Event handlers for type tabs
    document.querySelectorAll('.tab-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
            btn.classList.add('active');
            currentType = btn.dataset.type;
            clearSelections();
            loadFullRankings();
            // Clear detail panel
            detailPlaceholder.style.display = 'block';
            detailContent.style.display = 'none';
        });
    });

    // Event handlers for sortable headers
    document.querySelectorAll('.stats-table th.sortable').forEach(function(th) {
        th.addEventListener('click', function() {
            var field = th.dataset.sort;
            if (currentSort.field === field) {
                currentSort.direction = currentSort.direction === 'asc' ? 'desc' : 'asc';
            } else {
                currentSort.field = field;
                currentSort.direction = field === 'name' ? 'asc' : 'desc';
            }
            updateSortIndicator();
            renderTable();
        });
    });

    // Compare button
    compareBtn.addEventListener('click', loadComparison);

    // Clear selection button
    clearSelectionBtn.addEventListener('click', clearSelections);

    // WebSocket for real-time updates
    var socket;
    function connectWebSocket() {
        var wsProtocol = window.location.protocol === "https:" ? "wss://" : "ws://";
        socket = new WebSocket(wsProtocol + window.location.host + "/ws");

        socket.onopen = function() {
            console.log("Stats WebSocket connected");
        };

        socket.onmessage = function(event) {
            var msg = JSON.parse(event.data);
            if (msg.type === "geo") {
                updateFromGeo(msg.data);
            }
        };

        socket.onclose = function() {
            console.log("Stats WebSocket disconnected. Reconnecting in 3 seconds...");
            setTimeout(connectWebSocket, 3000);
        };

        socket.onerror = function(error) {
            console.error("Stats WebSocket error:", error);
            socket.close();
        };
    }

    // Update counts from real-time geo data
    function updateFromGeo(data) {
        // Filter by service if not showing "all"
        var serviceName = getServiceName(data.protocol, data.servicePort);
        if (currentService !== 'all' && serviceName !== currentService) {
            return;
        }

        var name;
        if (currentType === 'country') {
            name = data.dir === "out" ? data.dstCountry : data.srcCountry;
        } else {
            name = data.dir === "out" ? data.dstAsnOrg : data.srcAsnOrg;
        }

        if (!name) return;

        // Find and update the item in allItems
        var found = false;
        for (var i = 0; i < allItems.length; i++) {
            if (allItems[i].name === name) {
                allItems[i].count++;
                found = true;
                break;
            }
        }

        // Add new item if not found
        if (!found) {
            allItems.push({ name: name, count: 1 });
        }

        renderTable();
    }

    // Periodic sync with database to stay accurate
    function startPeriodicSync() {
        setInterval(function() {
            loadFullRankings();
        }, 30000); // Every 30 seconds
    }

    // Initialize
    if (typeof Chart !== 'undefined') {
        initDetailChart();
        setupServiceFilter();
        loadServices();
        loadFullRankings();
        connectWebSocket();
        startPeriodicSync();
    } else {
        console.error('Chart.js not loaded');
        tableBody.innerHTML = '<tr><td colspan="3">Error: Chart.js not loaded</td></tr>';
    }
});
