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

    // Real-time stats tracking
    var countryCounts = {};
    var asnCounts = {};

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

    // Load historical stats and populate local tracking objects
    function loadHistoricalLists() {
        var range = historyRangeSelect.value;

        fetch('/api/stats/top?type=country&range=' + range + '&limit=100')
            .then(function(response) { return response.json(); })
            .then(function(data) {
                // Reset and populate country counts from historical data
                countryCounts = {};
                if (data.items) {
                    data.items.forEach(function(item) {
                        countryCounts[item.name] = item.count;
                    });
                }
                renderTopCountries();
            })
            .catch(function(err) {
                console.error('Failed to load country stats:', err);
            });

        fetch('/api/stats/top?type=asn&range=' + range + '&limit=100')
            .then(function(response) { return response.json(); })
            .then(function(data) {
                // Reset and populate ASN counts from historical data
                asnCounts = {};
                if (data.items) {
                    data.items.forEach(function(item) {
                        asnCounts[item.name] = item.count;
                    });
                }
                renderTopAsns();
            })
            .catch(function(err) {
                console.error('Failed to load ASN stats:', err);
            });
    }

    // Get top 5 from counts object
    function getTop5(counts) {
        return Object.keys(counts)
            .map(function(name) { return { name: name, count: counts[name] }; })
            .sort(function(a, b) { return b.count - a.count; })
            .slice(0, 5);
    }

    // Render top countries list
    function renderTopCountries() {
        topCountriesList.innerHTML = buildListHtml(getTop5(countryCounts));
    }

    // Render top ASNs list
    function renderTopAsns() {
        topAsnsList.innerHTML = buildListHtml(getTop5(asnCounts));
    }

    // Increment stats from a geo message
    function updateStatsFromGeo(data) {
        var country, asn;
        if (data.dir === "out") {
            country = data.dstCountry;
            asn = data.dstAsnOrg;
        } else {
            country = data.srcCountry;
            asn = data.srcAsnOrg;
        }
        if (country) {
            countryCounts[country] = (countryCounts[country] || 0) + 1;
            renderTopCountries();
        }
        if (asn) {
            asnCounts[asn] = (asnCounts[asn] || 0) + 1;
            renderTopAsns();
        }
    }

    // Load historical data
    loadHistoricalLists();

    // Sync with database every 30 seconds to stay accurate
    setInterval(loadHistoricalLists, 30 * 1000);

    // Reload when range changes
    historyRangeSelect.addEventListener('change', loadHistoricalLists);


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
                updateStatsFromGeo(msg.data);
            }
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