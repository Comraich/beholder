package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/oschwald/maxminddb-golang"
	_ "modernc.org/sqlite"
)

// --- Constants ---
const (
	// Packet capture
	defaultSnapshotLen = 1024

	// WebSocket
	clientSendBufferSize = 256

	// Debouncing
	debounceDuration      = 1 * time.Second
	debounceCleanupPeriod = 5 * time.Minute

	// Stats broadcasting
	statsBroadcastInterval = 2 * time.Second

	// Historical stats
	statsChannelBuffer   = 10000
	statsFlushInterval   = 1 * time.Minute
	statsCleanupBatchSize = 1000

	// Public IP refresh
	publicIPRefreshInterval = 1 * time.Hour
)

// --- Configuration ---
var (
	iface              string
	dbCityPath         string
	dbAsnPath          string
	webServerPort      string
	staticDir          string
	allowedOrigins     []string
	statsDBPath        string
	statsRetentionDays int
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

	// Parse allowed origins (comma-separated, empty means same-origin only)
	if origins := getEnv("BEHOLDER_ALLOWED_ORIGINS", ""); origins != "" {
		for _, o := range strings.Split(origins, ",") {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				allowedOrigins = append(allowedOrigins, trimmed)
			}
		}
	}

	// Stats database configuration
	statsDBPath = getEnv("BEHOLDER_STATS_DB", "beholder_stats.db")
	retentionStr := getEnv("BEHOLDER_STATS_RETENTION_DAYS", "30")
	var err error
	statsRetentionDays, err = strconv.Atoi(retentionStr)
	if err != nil || statsRetentionDays < 1 {
		statsRetentionDays = 30
	}

	log.Printf("Configuration loaded:")
	log.Printf("  Interface: %s", iface)
	log.Printf("  Port: %s", webServerPort)
	log.Printf("  City DB: %s", dbCityPath)
	log.Printf("  ASN DB: %s", dbAsnPath)
	log.Printf("  Static Dir: %s", staticDir)
	log.Printf("  Stats DB: %s", statsDBPath)
	log.Printf("  Stats Retention: %d days", statsRetentionDays)
	if len(allowedOrigins) > 0 {
		log.Printf("  Allowed Origins: %v", allowedOrigins)
	} else {
		log.Printf("  Allowed Origins: same-origin only")
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists && value != "" {
		return value
	}
	return defaultValue
}

func checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // No origin header (e.g., same-origin or non-browser)
	}

	// If allowed origins configured, check against list
	if len(allowedOrigins) > 0 {
		for _, allowed := range allowedOrigins {
			if origin == allowed {
				return true
			}
		}
		log.Printf("WebSocket origin rejected: %s", origin)
		return false
	}

	// Default: same-origin check
	host := r.Host
	// Origin is like "http://example.com" or "https://example.com:8080"
	// Extract host from origin for comparison
	originHost := strings.TrimPrefix(origin, "https://")
	originHost = strings.TrimPrefix(originHost, "http://")

	if originHost == host {
		return true
	}

	log.Printf("WebSocket origin rejected (not same-origin): %s", origin)
	return false
}

// ---------------------

// --- Global Variables ---
var (
	snapshotLen int32         = defaultSnapshotLen
	promiscuous bool          = true
	timeout     time.Duration = pcap.BlockForever
	dbCity      *maxminddb.Reader
	dbASN       *maxminddb.Reader
	seenPairs   = &sync.Map{}
	clients          = make(map[*Client]bool)
	clientsLock      = sync.RWMutex{}
	upgrader         = websocket.Upgrader{
		CheckOrigin: checkOrigin,
	}
	MY_PUBLIC_IP    string
	MY_PUBLIC_IP_V6 string
	ipLock          sync.RWMutex
	countryCounts   atomic.Pointer[sync.Map]
	asnCounts       atomic.Pointer[sync.Map]

	// Historical stats
	statsDB      *sql.DB
	statsChannel = make(chan statsEvent, statsChannelBuffer)

	// GeoIP cache
	geoCache = &sync.Map{}
)

// statsEvent represents a single packet event for historical aggregation
type statsEvent struct {
	country string
	asnOrg  string
	service string
}

// hourlyBuffer holds in-memory aggregations before flushing to SQLite
// Uses composite keys: "country|service" and "asn|service"
type hourlyBuffer struct {
	sync.Mutex
	countryService map[string]int // key: "country|service"
	asnService     map[string]int // key: "asn|service"
	hourBucket     int64
}

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

// geoCacheEntry holds cached GeoIP lookup results
type geoCacheEntry struct {
	city    GeoRecord
	asn     ASRecord
	valid   bool
	created time.Time
}

const geoCacheMaxAge = 1 * time.Hour

func lookupGeoIP(ip net.IP) (GeoRecord, ASRecord, bool) {
	ipStr := ip.String()

	// Check cache first
	if cached, ok := geoCache.Load(ipStr); ok {
		entry := cached.(*geoCacheEntry)
		if time.Since(entry.created) < geoCacheMaxAge {
			return entry.city, entry.asn, entry.valid
		}
		// Expired, will refresh below
	}

	// Perform lookups
	var cityRecord GeoRecord
	var asnRecord ASRecord
	valid := true

	if err := dbCity.Lookup(ip, &cityRecord); err != nil || cityRecord.Location.Latitude == 0 {
		valid = false
	}
	_ = dbASN.Lookup(ip, &asnRecord)

	// Cache the result
	geoCache.Store(ipStr, &geoCacheEntry{
		city:    cityRecord,
		asn:     asnRecord,
		valid:   valid,
		created: time.Now(),
	})

	return cityRecord, asnRecord, valid
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

// getServiceName maps protocol and port to a friendly service name
func getServiceName(protocol string, port int) string {
	if protocol == "TCP" {
		switch port {
		case 80, 8080:
			return "HTTP"
		case 443, 8443:
			return "HTTPS"
		case 22:
			return "SSH"
		case 21:
			return "FTP"
		case 20:
			return "FTP-Data"
		case 25, 587:
			return "SMTP"
		case 110:
			return "POP3"
		case 143:
			return "IMAP"
		case 993:
			return "IMAPS"
		case 995:
			return "POP3S"
		case 23:
			return "Telnet"
		case 3389:
			return "RDP"
		case 5900, 5901:
			return "VNC"
		case 3306:
			return "MySQL"
		case 5432:
			return "PostgreSQL"
		case 27017:
			return "MongoDB"
		case 6379:
			return "Redis"
		case 11211:
			return "Memcached"
		case 445:
			return "SMB"
		case 139:
			return "NetBIOS"
		case 1433:
			return "MSSQL"
		case 1521:
			return "Oracle"
		case 6667, 6697:
			return "IRC"
		}
	} else if protocol == "UDP" {
		switch port {
		case 53:
			return "DNS"
		case 123:
			return "NTP"
		case 161, 162:
			return "SNMP"
		case 67, 68:
			return "DHCP"
		case 69:
			return "TFTP"
		case 514:
			return "Syslog"
		case 1900:
			return "SSDP"
		case 5353:
			return "mDNS"
		case 51820:
			return "WireGuard"
		case 500, 4500:
			return "IPSec"
		case 1194:
			return "OpenVPN"
		}
	}
	return "Other"
}
type StatsData struct {
	TopCountries []StatItem `json:"topCountries"`
	TopASNs      []StatItem `json:"topASNs"`
}

// --- WebSocket Hub ---
type ClientMessage struct {
	Type string `json:"type"`
	Info string `json:"info"`
}

// Client represents a connected WebSocket client with its own send channel
type Client struct {
	conn *websocket.Conn
	send chan WebSocketMessage
}

func broadcast(msg WebSocketMessage) {
	clientsLock.RLock()
	defer clientsLock.RUnlock()

	for client := range clients {
		select {
		case client.send <- msg:
			// Message queued
		default:
			// Client buffer full, skip this message for this client
		}
	}
}

func (c *Client) writePump() {
	defer func() {
		c.conn.Close()
		clientsLock.Lock()
		delete(clients, c)
		clientsLock.Unlock()
	}()

	for msg := range c.send {
		if err := c.conn.WriteJSON(msg); err != nil {
			log.Printf("WebSocket write error: %v", err)
			return
		}
	}
}

func (c *Client) readPump() {
	defer func() {
		close(c.send)
	}()

	for {
		var msg ClientMessage
		err := c.conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("Client disconnected (unexpected): %v", err)
			} else {
				log.Println("Client disconnected (normal).")
			}
			return
		}
		if msg.Type == "click" {
			log.Printf("[CLIENT CLICK] Info: %s", msg.Info)
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

	client := &Client{
		conn: conn,
		send: make(chan WebSocketMessage, clientSendBufferSize),
	}

	clientsLock.Lock()
	clients[client] = true
	clientsLock.Unlock()

	go client.writePump()
	client.readPump()
}

// --- IP/Web Server Functions ---
func getPublicIP(url string) (string, error) {
	resp, err := http.Get(url)
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
		return "", fmt.Errorf("not a valid IP from %s: %s", url, ip)
	}
	return ip, nil
}

func getPublicIPv4() (string, error) {
	return getPublicIP("https://api.ipify.org")
}

func getPublicIPv6() (string, error) {
	return getPublicIP("https://api6.ipify.org")
}

func updatePublicIPLoop() {
	log.Println("Starting public IP auto-updater...")
	for {
		// Update IPv4
		if ip, err := getPublicIPv4(); err != nil {
			log.Printf("Error updating public IPv4: %v", err)
		} else {
			ipLock.Lock()
			if ip != MY_PUBLIC_IP {
				log.Printf("Public IPv4 changed: %s", ip)
				MY_PUBLIC_IP = ip
			}
			ipLock.Unlock()
		}

		// Update IPv6 (may fail if no IPv6 connectivity)
		if ip, err := getPublicIPv6(); err == nil {
			ipLock.Lock()
			if ip != MY_PUBLIC_IP_V6 {
				log.Printf("Public IPv6 changed: %s", ip)
				MY_PUBLIC_IP_V6 = ip
			}
			ipLock.Unlock()
		}
		time.Sleep(publicIPRefreshInterval)
	}
}

// --- Stats Functions ---

func getTop5(m *sync.Map) []StatItem {
	var items []StatItem
	m.Range(func(key, value interface{}) bool {
		items = append(items, StatItem{
			Name:  key.(string),
			Count: int(value.(*atomic.Int64).Load()),
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
	// Try to load existing counter
	if val, ok := m.Load(key); ok {
		val.(*atomic.Int64).Add(1)
		return
	}
	// Create new counter
	newCounter := &atomic.Int64{}
	newCounter.Store(1)
	// LoadOrStore handles race where another goroutine created it first
	if existing, loaded := m.LoadOrStore(key, newCounter); loaded {
		existing.(*atomic.Int64).Add(1)
	}
}

// --- Historical Stats Database Functions ---

func initStatsDB() error {
	var err error
	statsDB, err = sql.Open("sqlite", statsDBPath)
	if err != nil {
		return fmt.Errorf("failed to open stats database: %w", err)
	}

	// Set pragmas for better performance
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=10000",
		"PRAGMA auto_vacuum=INCREMENTAL",
	}
	for _, pragma := range pragmas {
		if _, err := statsDB.Exec(pragma); err != nil {
			return fmt.Errorf("failed to set pragma: %w", err)
		}
	}

	// Check if migration is needed (old schema without service column)
	needsMigration := false
	var colCount int
	err = statsDB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('country_stats') WHERE name='service'").Scan(&colCount)
	if err == nil && colCount == 0 {
		// Table exists but doesn't have service column
		needsMigration = true
	}

	if needsMigration {
		log.Println("Migrating stats database to new schema with service column...")
		// Drop old tables (stats data is transient, 30-day retention)
		_, _ = statsDB.Exec("DROP TABLE IF EXISTS country_stats")
		_, _ = statsDB.Exec("DROP TABLE IF EXISTS asn_stats")
		log.Println("Old stats tables dropped")
	}

	// Create tables with service column
	schema := `
	CREATE TABLE IF NOT EXISTS country_stats (
		country TEXT NOT NULL,
		service TEXT NOT NULL DEFAULT 'Other',
		hour_bucket INTEGER NOT NULL,
		packet_count INTEGER NOT NULL DEFAULT 0,
		UNIQUE(country, service, hour_bucket)
	);

	CREATE TABLE IF NOT EXISTS asn_stats (
		asn_org TEXT NOT NULL,
		service TEXT NOT NULL DEFAULT 'Other',
		hour_bucket INTEGER NOT NULL,
		packet_count INTEGER NOT NULL DEFAULT 0,
		UNIQUE(asn_org, service, hour_bucket)
	);

	CREATE INDEX IF NOT EXISTS idx_country_stats_hour ON country_stats(hour_bucket);
	CREATE INDEX IF NOT EXISTS idx_country_stats_service ON country_stats(service);
	CREATE INDEX IF NOT EXISTS idx_asn_stats_hour ON asn_stats(hour_bucket);
	CREATE INDEX IF NOT EXISTS idx_asn_stats_service ON asn_stats(service);
	`
	if _, err := statsDB.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

func getCurrentHourBucket() int64 {
	return time.Now().Truncate(time.Hour).Unix()
}

func newHourlyBuffer() *hourlyBuffer {
	return &hourlyBuffer{
		countryService: make(map[string]int),
		asnService:     make(map[string]int),
		hourBucket:     getCurrentHourBucket(),
	}
}

func (b *hourlyBuffer) add(evt statsEvent) {
	b.Lock()
	defer b.Unlock()

	// Check if we've moved to a new hour
	currentHour := getCurrentHourBucket()
	if currentHour != b.hourBucket {
		// Flush old data and reset
		b.flushLocked()
		b.hourBucket = currentHour
	}

	service := evt.service
	if service == "" {
		service = "Other"
	}

	if evt.country != "" {
		key := evt.country + "|" + service
		b.countryService[key]++
	}
	if evt.asnOrg != "" {
		key := evt.asnOrg + "|" + service
		b.asnService[key]++
	}
}

func (b *hourlyBuffer) flush() {
	b.Lock()
	defer b.Unlock()
	b.flushLocked()
}

func (b *hourlyBuffer) flushLocked() {
	if len(b.countryService) == 0 && len(b.asnService) == 0 {
		return
	}

	tx, err := statsDB.Begin()
	if err != nil {
		log.Printf("Stats DB transaction error: %v", err)
		return
	}
	defer tx.Rollback()

	// UPSERT countries with service
	countryStmt, err := tx.Prepare(`
		INSERT INTO country_stats (country, service, hour_bucket, packet_count)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(country, service, hour_bucket) DO UPDATE SET
		packet_count = packet_count + excluded.packet_count
	`)
	if err != nil {
		log.Printf("Stats DB prepare error (country): %v", err)
		return
	}
	defer countryStmt.Close()

	for key, count := range b.countryService {
		parts := strings.SplitN(key, "|", 2)
		if len(parts) != 2 {
			continue
		}
		country, service := parts[0], parts[1]
		if _, err := countryStmt.Exec(country, service, b.hourBucket, count); err != nil {
			log.Printf("Stats DB insert error (country): %v", err)
		}
	}

	// UPSERT ASNs with service
	asnStmt, err := tx.Prepare(`
		INSERT INTO asn_stats (asn_org, service, hour_bucket, packet_count)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(asn_org, service, hour_bucket) DO UPDATE SET
		packet_count = packet_count + excluded.packet_count
	`)
	if err != nil {
		log.Printf("Stats DB prepare error (asn): %v", err)
		return
	}
	defer asnStmt.Close()

	for key, count := range b.asnService {
		parts := strings.SplitN(key, "|", 2)
		if len(parts) != 2 {
			continue
		}
		asnOrg, service := parts[0], parts[1]
		if _, err := asnStmt.Exec(asnOrg, service, b.hourBucket, count); err != nil {
			log.Printf("Stats DB insert error (asn): %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Stats DB commit error: %v", err)
		return
	}

	// Clear the buffer
	b.countryService = make(map[string]int)
	b.asnService = make(map[string]int)
}

func aggregatorLoop() {
	log.Println("Starting stats aggregator...")
	buffer := newHourlyBuffer()
	flushTicker := time.NewTicker(statsFlushInterval)
	defer flushTicker.Stop()

	for {
		select {
		case evt := <-statsChannel:
			buffer.add(evt)
		case <-flushTicker.C:
			buffer.flush()
		}
	}
}

func cleanupStatsLoop() {
	log.Println("Starting stats cleanup scheduler...")

	for {
		now := time.Now()
		// Calculate next 3:00 AM
		next3AM := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, now.Location())
		if now.After(next3AM) {
			next3AM = next3AM.Add(24 * time.Hour)
		}
		sleepDuration := next3AM.Sub(now)
		log.Printf("Next stats cleanup scheduled for %s", next3AM.Format(time.RFC3339))

		time.Sleep(sleepDuration)
		cleanupOldStats()
	}
}

func cleanupOldStats() {
	log.Println("Running stats cleanup...")
	cutoff := time.Now().Add(-time.Duration(statsRetentionDays) * 24 * time.Hour).Unix()

	// Delete in batches to avoid long locks
	batchSize := statsCleanupBatchSize

	// Use explicit queries to avoid SQL injection patterns
	cleanupQueries := []struct {
		name  string
		query string
	}{
		{"country_stats", "DELETE FROM country_stats WHERE hour_bucket < ? LIMIT ?"},
		{"asn_stats", "DELETE FROM asn_stats WHERE hour_bucket < ? LIMIT ?"},
	}

	for _, q := range cleanupQueries {
		for {
			result, err := statsDB.Exec(q.query, cutoff, batchSize)
			if err != nil {
				log.Printf("Stats cleanup error (%s): %v", q.name, err)
				break
			}
			rowsAffected, _ := result.RowsAffected()
			if rowsAffected < int64(batchSize) {
				break // No more rows to delete
			}
		}
	}

	// Incremental vacuum to reclaim space without locking the database
	if _, err := statsDB.Exec("PRAGMA incremental_vacuum"); err != nil {
		log.Printf("Stats incremental_vacuum error: %v", err)
	}

	log.Println("Stats cleanup completed")
}

// --- API Handlers for Historical Stats ---

type TopStatsResponse struct {
	Items []StatItem `json:"items"`
	Range string     `json:"range"`
	Type  string     `json:"type"`
}

type TimeSeriesPoint struct {
	Timestamp int64 `json:"timestamp"`
	Count     int   `json:"count"`
}

type TimeSeriesResponse struct {
	Name   string            `json:"name"`
	Points []TimeSeriesPoint `json:"points"`
	Range  string            `json:"range"`
	Type   string            `json:"type"`
}

func parseRange(rangeStr string) (time.Duration, error) {
	switch rangeStr {
	case "1h":
		return 1 * time.Hour, nil
	case "12h":
		return 12 * time.Hour, nil
	case "24h":
		return 24 * time.Hour, nil
	case "7d":
		return 7 * 24 * time.Hour, nil
	case "30d":
		return 30 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("invalid range: %s (use 1h, 12h, 24h, 7d, or 30d)", rangeStr)
	}
}

func handleStatsTop(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rangeStr := r.URL.Query().Get("range")
	if rangeStr == "" {
		rangeStr = "24h"
	}
	rangeDuration, err := parseRange(rangeStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	statsType := r.URL.Query().Get("type")
	if statsType != "country" && statsType != "asn" {
		http.Error(w, "type must be 'country' or 'asn'", http.StatusBadRequest)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 10
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	// Optional service filter
	service := r.URL.Query().Get("service")

	cutoff := time.Now().Add(-rangeDuration).Truncate(time.Hour).Unix()

	var rows *sql.Rows
	if service == "" || service == "all" {
		// No service filter - aggregate across all services
		var query string
		if statsType == "country" {
			query = `
				SELECT country, SUM(packet_count) as total
				FROM country_stats
				WHERE hour_bucket >= ?
				GROUP BY country
				ORDER BY total DESC
				LIMIT ?
			`
		} else {
			query = `
				SELECT asn_org, SUM(packet_count) as total
				FROM asn_stats
				WHERE hour_bucket >= ?
				GROUP BY asn_org
				ORDER BY total DESC
				LIMIT ?
			`
		}
		rows, err = statsDB.Query(query, cutoff, limit)
	} else {
		// Filter by specific service
		var query string
		if statsType == "country" {
			query = `
				SELECT country, SUM(packet_count) as total
				FROM country_stats
				WHERE hour_bucket >= ? AND service = ?
				GROUP BY country
				ORDER BY total DESC
				LIMIT ?
			`
		} else {
			query = `
				SELECT asn_org, SUM(packet_count) as total
				FROM asn_stats
				WHERE hour_bucket >= ? AND service = ?
				GROUP BY asn_org
				ORDER BY total DESC
				LIMIT ?
			`
		}
		rows, err = statsDB.Query(query, cutoff, service, limit)
	}

	if err != nil {
		log.Printf("Stats query error: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var items []StatItem
	for rows.Next() {
		var item StatItem
		if err := rows.Scan(&item.Name, &item.Count); err != nil {
			log.Printf("Stats scan error: %v", err)
			continue
		}
		items = append(items, item)
	}

	if items == nil {
		items = []StatItem{}
	}

	response := TopStatsResponse{
		Items: items,
		Range: rangeStr,
		Type:  statsType,
	}

	json.NewEncoder(w).Encode(response)
}

func handleStatsTimeseries(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rangeStr := r.URL.Query().Get("range")
	if rangeStr == "" {
		rangeStr = "24h"
	}
	rangeDuration, err := parseRange(rangeStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	statsType := r.URL.Query().Get("type")
	if statsType != "country" && statsType != "asn" {
		http.Error(w, "type must be 'country' or 'asn'", http.StatusBadRequest)
		return
	}

	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name parameter required", http.StatusBadRequest)
		return
	}

	// Optional service filter
	service := r.URL.Query().Get("service")

	cutoff := time.Now().Add(-rangeDuration).Truncate(time.Hour).Unix()

	var rows *sql.Rows
	if service == "" || service == "all" {
		// No service filter - aggregate across all services
		var query string
		if statsType == "country" {
			query = `
				SELECT hour_bucket, SUM(packet_count) as total
				FROM country_stats
				WHERE country = ? AND hour_bucket >= ?
				GROUP BY hour_bucket
				ORDER BY hour_bucket ASC
			`
		} else {
			query = `
				SELECT hour_bucket, SUM(packet_count) as total
				FROM asn_stats
				WHERE asn_org = ? AND hour_bucket >= ?
				GROUP BY hour_bucket
				ORDER BY hour_bucket ASC
			`
		}
		rows, err = statsDB.Query(query, name, cutoff)
	} else {
		// Filter by specific service
		var query string
		if statsType == "country" {
			query = `
				SELECT hour_bucket, packet_count
				FROM country_stats
				WHERE country = ? AND hour_bucket >= ? AND service = ?
				ORDER BY hour_bucket ASC
			`
		} else {
			query = `
				SELECT hour_bucket, packet_count
				FROM asn_stats
				WHERE asn_org = ? AND hour_bucket >= ? AND service = ?
				ORDER BY hour_bucket ASC
			`
		}
		rows, err = statsDB.Query(query, name, cutoff, service)
	}

	if err != nil {
		log.Printf("Stats timeseries query error: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var points []TimeSeriesPoint
	for rows.Next() {
		var point TimeSeriesPoint
		if err := rows.Scan(&point.Timestamp, &point.Count); err != nil {
			log.Printf("Stats timeseries scan error: %v", err)
			continue
		}
		points = append(points, point)
	}

	if points == nil {
		points = []TimeSeriesPoint{}
	}

	response := TimeSeriesResponse{
		Name:   name,
		Points: points,
		Range:  rangeStr,
		Type:   statsType,
	}

	json.NewEncoder(w).Encode(response)
}

// ServiceCount represents a service with its packet count
type ServiceCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func handleStatsServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rangeStr := r.URL.Query().Get("range")
	if rangeStr == "" {
		rangeStr = "24h"
	}
	rangeDuration, err := parseRange(rangeStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cutoff := time.Now().Add(-rangeDuration).Truncate(time.Hour).Unix()

	query := `
		SELECT service, SUM(packet_count) as total
		FROM country_stats
		WHERE hour_bucket >= ?
		GROUP BY service
		ORDER BY total DESC
	`

	rows, err := statsDB.Query(query, cutoff)
	if err != nil {
		log.Printf("Stats services query error: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var services []ServiceCount
	for rows.Next() {
		var svc ServiceCount
		if err := rows.Scan(&svc.Name, &svc.Count); err != nil {
			log.Printf("Stats services scan error: %v", err)
			continue
		}
		services = append(services, svc)
	}

	if services == nil {
		services = []ServiceCount{}
	}

	json.NewEncoder(w).Encode(services)
}

// --- NEW: Goroutine to clean up the debounce cache ---
func cleanupSeenPairsLoop() {
	log.Println("Starting debounce cache janitor...")
	ticker := time.NewTicker(debounceCleanupPeriod)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-debounceCleanupPeriod)

		seenPairs.Range(func(key, value interface{}) bool {
			if value.(time.Time).Before(cutoff) {
				seenPairs.Delete(key)
			}
			return true
		})

		// Also clean up expired geo cache entries
		geoCacheCutoff := time.Now().Add(-geoCacheMaxAge)
		geoCache.Range(func(key, value interface{}) bool {
			if value.(*geoCacheEntry).created.Before(geoCacheCutoff) {
				geoCache.Delete(key)
			}
			return true
		})
	}
}

// --- Stats broadcasting goroutine ---
func broadcastStatsLoop() {
	log.Println("Starting stats broadcaster...")
	ticker := time.NewTicker(statsBroadcastInterval)
	defer ticker.Stop()

	for range ticker.C {
		// Atomically swap in new maps and get the old ones
		newCountryCounts := &sync.Map{}
		newAsnCounts := &sync.Map{}

		oldCountryCounts := countryCounts.Swap(newCountryCounts)
		oldAsnCounts := asnCounts.Swap(newAsnCounts)

		// Build the stats data from the old maps
		stats := StatsData{
			TopCountries: getTop5(oldCountryCounts),
			TopASNs:      getTop5(oldAsnCounts),
		}

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

	// Initialize atomic counter maps
	countryCounts.Store(&sync.Map{})
	asnCounts.Store(&sync.Map{})

	var err error

	// Initialize SQLite stats database
	if err = initStatsDB(); err != nil {
		log.Fatalf("Failed to initialize stats database: %v", err)
	}
	defer statsDB.Close()
	log.Println("Successfully opened stats database.")

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

	initialIP, err := getPublicIPv4()
	if err != nil {
		log.Fatalf("Could not get public IPv4 on startup: %v", err)
	}
	ipLock.Lock()
	MY_PUBLIC_IP = initialIP
	ipLock.Unlock()
	log.Printf("My public IPv4: %s", initialIP)

	// Try to get IPv6 (optional - may not have IPv6 connectivity)
	if initialIPv6, err := getPublicIPv6(); err == nil {
		ipLock.Lock()
		MY_PUBLIC_IP_V6 = initialIPv6
		ipLock.Unlock()
		log.Printf("My public IPv6: %s", initialIPv6)
	} else {
		log.Println("No IPv6 connectivity detected")
	}

	go updatePublicIPLoop()
	go broadcastStatsLoop()

	// --- Start the janitor ---
	go cleanupSeenPairsLoop()

	// --- Start historical stats goroutines ---
	go aggregatorLoop()
	go cleanupStatsLoop()

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
		http.HandleFunc("/apple-touch-icon.png", serveStatic("apple-touch-icon.png", "image/png"))
		http.HandleFunc("/favicon-32x32.png", serveStatic("favicon-32x32.png", "image/png"))
		http.HandleFunc("/favicon-16x16.png", serveStatic("favicon-16x16.png", "image/png"))
		http.HandleFunc("/android-chrome-192x192.png", serveStatic("android-chrome-192x192.png", "image/png"))
		http.HandleFunc("/android-chrome-512x512.png", serveStatic("android-chrome-512x512.png", "image/png"))
		http.HandleFunc("/favicon.ico", serveStatic("favicon.ico", "image/x-icon"))
		http.HandleFunc("/site.webmanifest", serveStatic("site.webmanifest", "application/manifest+json"))
		http.HandleFunc("/stats.html", serveStatic("stats.html", ""))
		http.HandleFunc("/stats.js", serveStatic("stats.js", "application/javascript"))
		http.HandleFunc("/ws", serveWs)

		// Historical stats API endpoints
		http.HandleFunc("/api/stats/top", handleStatsTop)
		http.HandleFunc("/api/stats/timeseries", handleStatsTimeseries)
		http.HandleFunc("/api/stats/services", handleStatsServices)
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
			srcIP, dstIP = ip.SrcIP, ip.DstIP
		default:
			continue
		}

		// Directional Logic - check against both IPv4 and IPv6 public IPs
		ipLock.RLock()
		publicIPv4 := MY_PUBLIC_IP
		publicIPv6 := MY_PUBLIC_IP_V6
		ipLock.RUnlock()

		srcStr := srcIP.String()
		dstStr := dstIP.String()
		srcIsHome := srcStr == publicIPv4 || srcStr == publicIPv6
		dstIsHome := dstStr == publicIPv4 || dstStr == publicIPv6
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

		// --- GeoIP Lookup (cached) ---
		remoteRecord, remoteAsnRecord, remoteValid := lookupGeoIP(remoteIP)
		if !remoteValid {
			continue
		}
		homeRecord, homeAsnRecord, _ := lookupGeoIP(homeIP)

		// --- Increment Counters ---
		countryName := remoteRecord.Country.Names["en"]
		asnOrgName := remoteAsnRecord.AutonomousSystemOrganization
		serviceName := getServiceName(protocol, servicePort)
		incrementCounter(countryCounts.Load(), countryName)
		incrementCounter(asnCounts.Load(), asnOrgName)

		// Send to historical stats channel (non-blocking)
		select {
		case statsChannel <- statsEvent{country: countryName, asnOrg: asnOrgName, service: serviceName}:
		default:
			// Channel full, drop event (packet capture never blocks)
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
