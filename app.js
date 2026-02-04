console.log('app.js loaded');
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOMContentLoaded fired');

    // 1. Initialize the map
    var map = L.map('map', { 
        minZoom: 2,
        maxBounds: [
            [-90, -180],
            [90, 180]
        ],
        worldCopyJump: false,
        zoomControl: true
    }).setView([20, 0], 2);

    // Create the custom Zoom Out button
    L.Control.ZoomOut = L.Control.extend({ 
        onAdd: function(map) {
            var button = L.DomUtil.create('a', 'custom-zoom-out');
            button.title = 'Zoom out to world';
            button.href = '#';
            button.role = 'button';
            L.DomEvent.disableClickPropagation(button);
            L.DomEvent.on(button, 'click', function(e) {
                e.preventDefault();
                map.setView([20, 0], 2);
            });
            return button;
        },
        onRemove: function(map) {}
    });
    L.control.zoomOut = function(opts) {
        return new L.Control.ZoomOut(opts);
    }

    // 2. Add a dark tile layer
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { /* ... (unchanged) ... */
        attribution: '&copy; <a href="https://openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
        maxZoom: 19,
        minZoom: 2,
        noWrap: true
    }).addTo(map);

    // Add the custom button to the map
    L.control.zoomOut({ position: 'topleft' }).addTo(map);

    // Get references
    var showIncomingCheckbox = document.getElementById('showIncoming');
    var showOutgoingCheckbox = document.getElementById('showOutgoing');
    var infoPane = document.getElementById('info-pane');
    var infoPaneDefault = '<p>Click a dot for info</p>';
    var topCountriesList = document.getElementById('top-countries');
    var topAsnsList = document.getElementById('top-asns');
    var historyRangeSelect = document.getElementById('history-range');

    // Chart colors for top 5 items
    var chartColors = [
        'rgba(255, 99, 132, 0.8)',   // Red
        'rgba(54, 162, 235, 0.8)',   // Blue
        'rgba(255, 206, 86, 0.8)',   // Yellow
        'rgba(75, 192, 192, 0.8)',   // Teal
        'rgba(153, 102, 255, 0.8)'   // Purple
    ];

    // Initialize charts
    var countryChart = null;
    var asnChart = null;

    function initCharts() {
        var commonOptions = {
            responsive: false,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#ccc',
                        font: { size: 10 },
                        boxWidth: 12,
                        padding: 8
                    }
                }
            },
            scales: {
                x: {
                    display: false
                },
                y: {
                    ticks: { color: '#888', font: { size: 10 } },
                    grid: { color: 'rgba(255,255,255,0.1)' }
                }
            }
        };

        var countryCtx = document.getElementById('country-chart').getContext('2d');
        countryChart = new Chart(countryCtx, {
            type: 'line',
            data: { labels: [], datasets: [] },
            options: commonOptions
        });

        var asnCtx = document.getElementById('asn-chart').getContext('2d');
        asnChart = new Chart(asnCtx, {
            type: 'line',
            data: { labels: [], datasets: [] },
            options: commonOptions
        });
    }

    function loadHistoricalStats() {
        var range = historyRangeSelect.value;
        loadTopStats('country', range);
        loadTopStats('asn', range);
    }

    function loadTopStats(type, range) {
        fetch('/api/stats/top?type=' + type + '&range=' + range + '&limit=5')
            .then(function(response) { return response.json(); })
            .then(function(data) {
                if (data.items && data.items.length > 0) {
                    loadTimeseriesForTop(type, range, data.items);
                } else {
                    // Clear chart if no data
                    var chart = type === 'country' ? countryChart : asnChart;
                    chart.data.labels = [];
                    chart.data.datasets = [];
                    chart.update();
                }
            })
            .catch(function(err) {
                console.error('Failed to load top stats:', err);
            });
    }

    function loadTimeseriesForTop(type, range, topItems) {
        var promises = topItems.map(function(item) {
            return fetch('/api/stats/timeseries?type=' + type + '&range=' + range + '&name=' + encodeURIComponent(item.name))
                .then(function(response) { return response.json(); });
        });

        Promise.all(promises).then(function(results) {
            var chart = type === 'country' ? countryChart : asnChart;

            // Collect all unique timestamps
            var allTimestamps = new Set();
            results.forEach(function(result) {
                if (result.points) {
                    result.points.forEach(function(p) { allTimestamps.add(p.timestamp); });
                }
            });

            // Sort timestamps
            var sortedTimestamps = Array.from(allTimestamps).sort(function(a, b) { return a - b; });

            // Create labels
            var labels = sortedTimestamps.map(function(ts) {
                var date = new Date(ts * 1000);
                if (range === '24h') {
                    return date.getHours() + ':00';
                } else {
                    return (date.getMonth() + 1) + '/' + date.getDate();
                }
            });

            // Create datasets
            var datasets = results.map(function(result, index) {
                var dataMap = {};
                if (result.points) {
                    result.points.forEach(function(p) { dataMap[p.timestamp] = p.count; });
                }

                var data = sortedTimestamps.map(function(ts) {
                    return dataMap[ts] || 0;
                });

                return {
                    label: result.name || topItems[index].name,
                    data: data,
                    borderColor: chartColors[index],
                    backgroundColor: chartColors[index].replace('0.8', '0.2'),
                    borderWidth: 2,
                    pointRadius: 0,
                    tension: 0.3,
                    fill: false
                };
            });

            console.log('Updating chart:', type, 'labels:', labels.length, 'datasets:', datasets.length);
            chart.data.labels = labels;
            chart.data.datasets = datasets;
            chart.update();
        }).catch(function(err) {
            console.error('Failed to load timeseries:', err);
        });
    }

    // Build HTML for stats lists
    function buildListHtml(list) {
        var html = "";
        if (!list || list.length === 0) {
            return "<li><span class='stat-name'>No data yet...</span></li>";
        }
        list.forEach(function(item) {
            html += "<li>" +
                        "<span class='stat-name'>" + (item.name || "Unknown") + "</span>" +
                        "<span class='stat-count'>" + formatCount(item.count) + "</span>" +
                    "</li>";
        });
        return html;
    }

    // Format large numbers with K/M suffix
    function formatCount(count) {
        if (count >= 1000000) {
            return (count / 1000000).toFixed(1) + 'M';
        } else if (count >= 1000) {
            return (count / 1000).toFixed(1) + 'K';
        }
        return count.toString();
    }

    // Load historical stats for the lists
    function loadHistoricalLists() {
        var range = historyRangeSelect.value;

        fetch('/api/stats/top?type=country&range=' + range + '&limit=5')
            .then(function(response) { return response.json(); })
            .then(function(data) {
                topCountriesList.innerHTML = buildListHtml(data.items);
            })
            .catch(function(err) {
                console.error('Failed to load country stats:', err);
            });

        fetch('/api/stats/top?type=asn&range=' + range + '&limit=5')
            .then(function(response) { return response.json(); })
            .then(function(data) {
                topAsnsList.innerHTML = buildListHtml(data.items);
            })
            .catch(function(err) {
                console.error('Failed to load ASN stats:', err);
            });
    }

    // Initialize charts and load historical data
    console.log('Chart.js loaded:', typeof Chart !== 'undefined');
    if (typeof Chart !== 'undefined') {
        console.log('Initializing charts...');
        initCharts();
        loadHistoricalStats();
        loadHistoricalLists();

        // Refresh every 5 minutes
        setInterval(function() {
            loadHistoricalStats();
            loadHistoricalLists();
        }, 5 * 60 * 1000);

        // Reload when range changes
        historyRangeSelect.addEventListener('change', function() {
            loadHistoricalStats();
            loadHistoricalLists();
        });
    } else {
        // Chart.js not loaded, still load the lists
        loadHistoricalLists();
        setInterval(loadHistoricalLists, 5 * 60 * 1000);
        historyRangeSelect.addEventListener('change', loadHistoricalLists);
    }


    // 3. Set up the WebSocket connection 
    var socket;
    function connect() {
        var wsProtocol = window.location.protocol === "https:" ? "wss://" : "ws://";
        socket = new WebSocket(wsProtocol + window.location.host + "/ws");

        socket.onopen = function(event) {
            console.log("WebSocket connected!");
        };

        // Handle incoming messages
        socket.onmessage = function(event) {
            var msg = JSON.parse(event.data);
            if (msg.type === "geo") {
                drawConnection(msg.data);
            }
            // Note: stats are now loaded from historical API, not WebSocket
        };

        socket.onclose = function(event) {
            console.log("WebSocket disconnected. Reconnecting in 3 seconds...");
            setTimeout(connect, 3000); 
        };

        socket.onerror = function(error) {
            console.error("WebSocket error:", error);
            socket.close(); // This will trigger onclose, which triggers reconnect
        };
    }
    
    connect(); 


    // Reset info pane on map click
    map.on('click', function() {
        infoPane.innerHTML = infoPaneDefault;
    });

    // 5. Function to draw lines 
    function drawConnection(data) { 
        if (data.dir === "out" && !showOutgoingCheckbox.checked) { return; }
        if (data.dir === "in" && !showIncomingCheckbox.checked) { return; }
        var start = [data.srcLat, data.srcLon];
        var end = [data.dstLat, data.dstLon];
        var lineColor, circleColor;
        var popupCity, popupCountry, popupAsnOrg, remoteIP;
        var targetCoords;
        var isReversed = false;
        var arcDirection = 0;
        if (data.dir === "out") {
            lineColor = 'rgba(255, 0, 0, 0.5)';
            circleColor = '#f03';
            popupCity = data.dstCity || "Unknown";
            popupCountry = data.dstCountry || "Unknown";
            popupAsnOrg = data.dstAsnOrg || "";
            remoteIP = data.remoteIP || "";
            targetCoords = end;
            isReversed = false;
            arcDirection = 1;
        } else {
            lineColor = 'rgba(255, 255, 255, 0.5)';
            circleColor = '#fff';
            popupCity = data.srcCity || "Unknown";
            popupCountry = data.srcCountry || "Unknown";
            popupAsnOrg = data.srcAsnOrg || "";
            remoteIP = data.remoteIP || "";
            targetCoords = start; 
            isReversed = true;
            arcDirection = -1;
        }
        var midLat = (start[0] + end[0]) / 2;
        var midLon = (start[1] + end[1]) / 2;
        var offsetLat = (start[1] - end[1]) * 0.1 * arcDirection;
        var offsetLon = (start[0] - end[0]) * 0.1 * arcDirection * -1;
        var controlPoint = [midLat + offsetLat, midLon + offsetLon];
        var path = ['M', start, 'Q', controlPoint, end];
        var line = L.polyline.antPath(path, {
            "use": L.curve,
            "delay": 800,
            "dashArray": [10, 20],
            "weight": 3,
            "color": lineColor,
            "pulseColor": "#333",
            "hardwareAccelerated": true,
            "reverse": isReversed
        }).addTo(map);
        var serviceName = getFriendlyPortName(data.protocol, data.servicePort);
        var popupContent = '<p class="info-title">' + escapeHtml(popupCity) + '</p>';
        if (popupCountry) { popupContent += '<p class="info-country">' + escapeHtml(popupCountry) + '</p>'; }
        if (popupAsnOrg) {
            popupContent += '<hr class="info-divider">';
            popupContent += '<p class="info-asn">' + escapeHtml(popupAsnOrg) + '</p>';
        }
        if (remoteIP) { popupContent += '<p class="info-ip">' + escapeHtml(remoteIP) + '</p>'; }
        popupContent += '<p class="info-port">' + escapeHtml(serviceName) + '</p>'; 
        var dotLocation = (data.dir === "out") ? end : start;
        var circle = L.circleMarker(dotLocation, {
            color: circleColor,
            fillColor: circleColor,
            fillOpacity: 0.5,
            radius: 5
        });
        circle.on('click', function(e) {
            infoPane.innerHTML = popupContent;
            map.setView(targetCoords, 10);
            L.DomEvent.stopPropagation(e);
            var logMessage = {
                type: "click",
                info: popupContent
            };
            socket.send(JSON.stringify(logMessage));
        });
        circle.addTo(map);
        setTimeout(function() {
            map.removeLayer(line);
            map.removeLayer(circle);
        }, 3000);
    }

    // Escape HTML to prevent XSS
    function escapeHtml(str) {
        if (!str) return '';
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // getFriendlyPortName
    function getFriendlyPortName(proto, port) {
        if (proto === "TCP") {
            switch (port) {
                case 20: case 21: return "FTP";
                case 22: return "SSH";
                case 23: return "Telnet";
                case 25: return "SMTP";
                case 53: return "DNS";
                case 80: return "HTTP";
                case 110: return "POP3";
                case 143: return "IMAP";
                case 443: return "HTTPS";
                case 465: return "SMTPS";
                case 587: return "SMTP (Submission)";
                case 993: return "IMAPS";
                case 995: return "POP3S";
                case 3306: return "MySQL";
                case 3389: return "RDP";
                case 5432: return "PostgreSQL";
                case 5900: return "VNC";
                case 6379: return "Redis";
                case 8080: return "HTTP (Alt)";
                case 8443: return "HTTPS (Alt)";
                default: break;
            }
        }
        if (proto === "UDP") {
            switch (port) {
                case 53: return "DNS";
                case 67: case 68: return "DHCP";
                case 123: return "NTP";
                case 161: return "SNMP";
                case 443: return "QUIC";
                case 500: return "IKE (VPN)";
                case 1194: return "OpenVPN";
                case 51820: return "WireGuard";
                default: break;
            }
        }
        return proto + "/" + port;
    }

});