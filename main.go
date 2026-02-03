package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/oschwald/maxminddb-golang"
)

// --- Configuration ---
var (
	iface         string
	dbCityPath    string
	dbAsnPath     string
	webServerPort string
	staticDir     string
)

func loadConfig() {
	// Load .env file if it exists (ignore error if not found)
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using defaults/environment")
	}

	iface = getEnv("BEHOLDER_INTERFACE", "eth0")
	webServerPort = getEnv("BEHOLDER_PORT", ":8080")
	dbCityPath = getEnv("BEHOLDER_DB_CITY", "GeoLite2-City.mmdb")
	dbAsnPath = getEnv("BEHOLDER_DB_ASN", "GeoLite2-ASN.mmdb")
	staticDir = getEnv("BEHOLDER_STATIC_DIR", "")

	// If staticDir is empty, use current working directory
	if staticDir == "" {
		var err error
		staticDir, err = os.Getwd()
		if err != nil {
			log.Fatalf("Could not get working directory: %v", err)
		}
	}

	log.Printf("Configuration loaded:")
	log.Printf("  Interface: %s", iface)
	log.Printf("  Port: %s", webServerPort)
	log.Printf("  City DB: %s", dbCityPath)
	log.Printf("  ASN DB: %s", dbAsnPath)
	log.Printf("  Static Dir: %s", staticDir)
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists && value != "" {
		return value
	}
	return defaultValue
}

// ---------------------

// --- Global Variables ---
var (
	snapshotLen      int32         = 1024
	promiscuous      bool          = true
	timeout          time.Duration = pcap.BlockForever
	dbCity           *maxminddb.Reader
	dbASN            *maxminddb.Reader
	debounceDuration = 1 * time.Second
	seenPairs        = &sync.Map{}
	connections      = make(map[*websocket.Conn]bool)
	connLock         = sync.RWMutex{}
	upgrader         = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	MY_PUBLIC_IP  string
	ipLock        sync.RWMutex
	countryCounts = &sync.Map{}
	asnCounts     = &sync.Map{}
)

// --- Structs ---
type WebSocketMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}
type GeoRecord struct {
	Country struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}
type ASRecord struct {
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}
type GeoData struct {
	SrcLat      float64 `json:"srcLat"`
	SrcLon      float64 `json:"srcLon"`
	SrcCity     string  `json:"srcCity"`
	SrcCountry  string  `json:"srcCountry"`
	SrcAsnOrg   string  `json:"srcAsnOrg"`
	DstLat      float64 `json:"dstLat"`
	DstLon      float64 `json:"dstLon"`
	DstCity     string  `json:"dstCity"`
	DstCountry  string  `json:"dstCountry"`
	DstAsnOrg   string  `json:"dstAsnOrg"`
	Direction   string  `json:"dir"`
	ServicePort int     `json:"servicePort"`
	Protocol    string  `json:"protocol"`
	RemoteIP    string  `json:"remoteIP"`
}
type StatItem struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}
type StatsData struct {
	TopCountries []StatItem `json:"topCountries"`
	TopASNs      []StatItem `json:"topASNs"`
}

// --- WebSocket Hub (Unchanged) ---
type ClientMessage struct {
	Type string `json:"type"`
	Info string `json:"info"`
}

func broadcast(msg WebSocketMessage) {
	connLock.RLock()
	defer connLock.RUnlock()
	for conn := range connections {
		if err := conn.WriteJSON(msg); err != nil {
		}
	}
}
func serveWs(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}
	log.Println("New client connected!")
	connLock.Lock()
	connections[conn] = true
	connLock.Unlock()
	for {
		var msg ClientMessage
		err := conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Client disconnected (unexpected): %v", err)
			} else {
				log.Println("Client disconnected (normal).")
			}
			connLock.Lock()
			delete(connections, conn)
			connLock.Unlock()
			break
		}
		if msg.Type == "click" {
			log.Printf("[CLIENT CLICK] Info: %s", msg.Info)
		}
	}
}

// --- IP/Web Server Functions ---
func getPublicIP() (string, error) {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	ip := string(body)
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("not a valid IP from api.ipify.org: %s", ip)
	}
	return ip, nil
}
func updatePublicIPLoop() {
	log.Println("Starting public IP auto-updater...")
	for {
		ip, err := getPublicIP()
		if err != nil {
			log.Printf("Error updating public IP: %v", err)
		} else {
			ipLock.Lock()
			if ip != MY_PUBLIC_IP {
				log.Printf("Public IP changed! New IP: %s", ip)
				MY_PUBLIC_IP = ip
			}
			ipLock.Unlock()
		}
		time.Sleep(1 * time.Hour)
	}
}

// --- Stats Functions ---

func getTop5(m *sync.Map) []StatItem {
	var items []StatItem
	m.Range(func(key, value interface{}) bool {
		items = append(items, StatItem{
			Name:  key.(string),
			Count: value.(int),
		})
		return true
	})
	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})
	if len(items) > 5 {
		items = items[:5]
	}
	return items
}

func incrementCounter(m *sync.Map, key string) {
	if key == "" {
		return
	}
	count := 0
	if val, ok := m.Load(key); ok {
		count = val.(int)
	}
	m.Store(key, count+1)
}

// --- NEW: Goroutine to clean up the debounce cache ---
func cleanupSeenPairsLoop() {
	log.Println("Starting debounce cache janitor...")
	ticker := time.NewTicker(5 * time.Minute) // Run every 5 minutes
	defer ticker.Stop()

	for range ticker.C {
		// We set the cutoff to 5 minutes ago.
		// This means our debounce is effectively "once per 5 minutes"
		// which is fine. We can adjust debounceDuration if needed.
		cutoff := time.Now().Add(-5 * time.Minute)

		seenPairs.Range(func(key, value interface{}) bool {
			if value.(time.Time).Before(cutoff) {
				seenPairs.Delete(key) // Delete old entry
			}
			return true // Continue iterating
		})
	}
}

// --- Stats broadcasting goroutine ---
func broadcastStatsLoop() {
	log.Println("Starting stats broadcaster...")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// This atomically resets the counters *without*
		// blocking the main packet capture loop.
		newCountryCounts := &sync.Map{}
		newAsnCounts := &sync.Map{}

		oldCountryCounts := countryCounts
		oldAsnCounts := asnCounts

		countryCounts = newCountryCounts
		asnCounts = newAsnCounts

		// Build the stats data from the *old* maps
		stats := StatsData{
			TopCountries: getTop5(oldCountryCounts),
			TopASNs:      getTop5(oldAsnCounts),
		}

		// Wrap it in our WebSocketMessage
		msg := WebSocketMessage{
			Type: "stats",
			Data: stats,
		}
		broadcast(msg)
	}
}

// --- Main Application ---
func main() {
	loadConfig()

	var err error
	dbCity, err = maxminddb.Open(dbCityPath)
	if err != nil {
		log.Fatal(err)
	}
	defer dbCity.Close()
	log.Println("Successfully opened GeoIP City database.")

	dbASN, err = maxminddb.Open(dbAsnPath)
	if err != nil {
		log.Fatal(err)
	}
	defer dbASN.Close()
	log.Println("Successfully opened GeoIP ASN database.")

	initialIP, err := getPublicIP()
	if err != nil {
		log.Fatalf("Could not get public IP on startup: %v", err)
	}
	ipLock.Lock()
	MY_PUBLIC_IP = initialIP
	ipLock.Unlock()
	log.Printf("My public IP is: %s", initialIP)

	go updatePublicIPLoop()
	go broadcastStatsLoop()

	// --- Start the janitor ---
	go cleanupSeenPairsLoop()

	// Start Web Server
	go func() {
		serveStatic := func(path, contentType string) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				if contentType != "" {
					w.Header().Set("Content-Type", contentType)
				}
				http.ServeFile(w, r, filepath.Join(staticDir, path))
			}
		}

		http.HandleFunc("/", serveStatic("index.html", ""))
		http.HandleFunc("/style.css", serveStatic("style.css", "text/css"))
		http.HandleFunc("/app.js", serveStatic("app.js", "application/javascript"))
		http.HandleFunc("/leaflet.curve.js", serveStatic("leaflet.curve.js", "application/javascript"))
		http.HandleFunc("/apple-touch-icon.png", serveStatic("apple-touch-icon.png", "image/png"))
		http.HandleFunc("/favicon-32x32.png", serveStatic("favicon-32x32.png", "image/png"))
		http.HandleFunc("/favicon-16x16.png", serveStatic("favicon-16x16.png", "image/png"))
		http.HandleFunc("/android-chrome-192x192.png", serveStatic("android-chrome-192x192.png", "image/png"))
		http.HandleFunc("/android-chrome-512x512.png", serveStatic("android-chrome-512x512.png", "image/png"))
		http.HandleFunc("/favicon.ico", serveStatic("favicon.ico", "image/x-icon"))
		http.HandleFunc("/site.webmanifest", serveStatic("site.webmanifest", "application/manifest+json"))
		http.HandleFunc("/ws", serveWs)
		log.Printf("Starting web server on %s\n", webServerPort)
		if err := http.ListenAndServe(webServerPort, nil); err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}()

	// Start Packet Capture
	handle, err := pcap.OpenLive(iface, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	err = handle.SetBPFFilter("ip or ip6")
	if err != nil {
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	log.Printf("Capturing packets on interface %s...\n", iface)

	// --- Step 4: Main Loop ---
	for packet := range packetSource.Packets() {
		// Get Transport Layer ...
		transportLayer := packet.TransportLayer()
		if transportLayer == nil {
			continue
		}
		var srcPort, dstPort int
		var protocol string
		switch trans := transportLayer.(type) {
		case *layers.TCP:
			srcPort, dstPort, protocol = int(trans.SrcPort), int(trans.DstPort), "TCP"
		case *layers.UDP:
			srcPort, dstPort, protocol = int(trans.SrcPort), int(trans.DstPort), "UDP"
		default:
			continue
		}

		// Get Network Layer
		netLayer := packet.NetworkLayer()
		if netLayer == nil {
			continue
		}
		var srcIP, dstIP net.IP
		switch ip := netLayer.(type) {
		case *layers.IPv4:
			srcIP, dstIP = ip.SrcIP, ip.DstIP
		case *layers.IPv6:
			continue
		default:
			continue
		}

		// Directional Logic
		ipLock.RLock()
		currentPublicIP := MY_PUBLIC_IP
		ipLock.RUnlock()
		if currentPublicIP == "" {
			continue
		}
		srcIsHome := srcIP.String() == currentPublicIP
		dstIsHome := dstIP.String() == currentPublicIP
		var remoteIP, homeIP net.IP
		var direction string
		var servicePort int
		if srcIsHome && !dstIsHome {
			direction, remoteIP, homeIP, servicePort = "out", dstIP, srcIP, dstPort
		} else if !srcIsHome && dstIsHome {
			direction, remoteIP, homeIP, servicePort = "in", srcIP, dstIP, srcPort
		} else {
			continue
		}

		// --- Debounce Check ---
		// We *don't* check if it's too soon. We *always* count.
		// We only check if it's too soon to *draw the line*.
		pairKey := direction + "->" + remoteIP.String() + ":" + fmt.Sprintf("%d", servicePort)

		// --- GeoIP Lookup ---
		var remoteRecord GeoRecord
		var homeRecord GeoRecord
		var remoteAsnRecord ASRecord
		var homeAsnRecord ASRecord
		if err = dbCity.Lookup(remoteIP, &remoteRecord); err != nil || remoteRecord.Location.Latitude == 0 {
			continue
		}
		_ = dbASN.Lookup(remoteIP, &remoteAsnRecord)
		if err = dbCity.Lookup(homeIP, &homeRecord); err != nil {
			continue
		}
		_ = dbASN.Lookup(homeIP, &homeAsnRecord)

		// --- Increment Counters ---
		if direction == "in" {
			incrementCounter(countryCounts, remoteRecord.Country.Names["en"])
			incrementCounter(asnCounts, remoteAsnRecord.AutonomousSystemOrganization)
		} else { // "out"
			incrementCounter(countryCounts, remoteRecord.Country.Names["en"])
			incrementCounter(asnCounts, remoteAsnRecord.AutonomousSystemOrganization)
		}

		// --- Step 5: BROADCAST ---

		// Check if we should *draw the line* (debounce)
		if lastSeenTime, found := seenPairs.Load(pairKey); found {
			if time.Since(lastSeenTime.(time.Time)) < debounceDuration {
				continue // Too soon, don't draw
			}
		}
		seenPairs.Store(pairKey, time.Now()) // Store the new time

		var data GeoData
		if direction == "out" {
			data = GeoData{
				SrcLat: homeRecord.Location.Latitude, SrcLon: homeRecord.Location.Longitude, SrcCity: homeRecord.City.Names["en"], SrcCountry: homeRecord.Country.Names["en"], SrcAsnOrg: homeAsnRecord.AutonomousSystemOrganization,
				DstLat: remoteRecord.Location.Latitude, DstLon: remoteRecord.Location.Longitude, DstCity: remoteRecord.City.Names["en"], DstCountry: remoteRecord.Country.Names["en"], DstAsnOrg: remoteAsnRecord.AutonomousSystemOrganization,
				Direction: "out", ServicePort: servicePort, Protocol: protocol, RemoteIP: remoteIP.String(),
			}
		} else {
			data = GeoData{
				SrcLat: remoteRecord.Location.Latitude, SrcLon: remoteRecord.Location.Longitude, SrcCity: remoteRecord.City.Names["en"], SrcCountry: remoteRecord.Country.Names["en"], SrcAsnOrg: remoteAsnRecord.AutonomousSystemOrganization,
				DstLat: homeRecord.Location.Latitude, DstLon: homeRecord.Location.Longitude, DstCity: homeRecord.City.Names["en"], DstCountry: homeRecord.Country.Names["en"], DstAsnOrg: homeAsnRecord.AutonomousSystemOrganization,
				Direction: "in", ServicePort: servicePort, Protocol: protocol, RemoteIP: remoteIP.String(),
			}
		}
		// Send the "geo" message
		broadcast(WebSocketMessage{Type: "geo", Data: data})
	}
}

// isPrivateIP function
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && (ip4[1] >= 16 && ip4[1] <= 31)) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	return ip.IsPrivate()
}
