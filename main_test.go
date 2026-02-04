package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// --- getServiceName tests ---

func TestGetServiceName_TCP(t *testing.T) {
	tests := []struct {
		port     int
		expected string
	}{
		{80, "HTTP"},
		{8080, "HTTP"},
		{443, "HTTPS"},
		{8443, "HTTPS"},
		{22, "SSH"},
		{21, "FTP"},
		{20, "FTP-Data"},
		{25, "SMTP"},
		{587, "SMTP"},
		{110, "POP3"},
		{143, "IMAP"},
		{993, "IMAPS"},
		{995, "POP3S"},
		{23, "Telnet"},
		{3389, "RDP"},
		{5900, "VNC"},
		{5901, "VNC"},
		{3306, "MySQL"},
		{5432, "PostgreSQL"},
		{27017, "MongoDB"},
		{6379, "Redis"},
		{11211, "Memcached"},
		{445, "SMB"},
		{139, "NetBIOS"},
		{1433, "MSSQL"},
		{1521, "Oracle"},
		{6667, "IRC"},
		{6697, "IRC"},
		{12345, "Other"}, // Unknown port
	}

	for _, tt := range tests {
		result := getServiceName("TCP", tt.port)
		if result != tt.expected {
			t.Errorf("getServiceName(TCP, %d) = %q; want %q", tt.port, result, tt.expected)
		}
	}
}

func TestGetServiceName_UDP(t *testing.T) {
	tests := []struct {
		port     int
		expected string
	}{
		{53, "DNS"},
		{123, "NTP"},
		{161, "SNMP"},
		{162, "SNMP"},
		{67, "DHCP"},
		{68, "DHCP"},
		{69, "TFTP"},
		{514, "Syslog"},
		{1900, "SSDP"},
		{5353, "mDNS"},
		{51820, "WireGuard"},
		{500, "IPSec"},
		{4500, "IPSec"},
		{1194, "OpenVPN"},
		{9999, "Other"}, // Unknown port
	}

	for _, tt := range tests {
		result := getServiceName("UDP", tt.port)
		if result != tt.expected {
			t.Errorf("getServiceName(UDP, %d) = %q; want %q", tt.port, result, tt.expected)
		}
	}
}

func TestGetServiceName_UnknownProtocol(t *testing.T) {
	result := getServiceName("ICMP", 80)
	if result != "Other" {
		t.Errorf("getServiceName(ICMP, 80) = %q; want %q", result, "Other")
	}
}

// --- parseRange tests ---

func TestParseRange_ValidRanges(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"1h", 1 * time.Hour},
		{"12h", 12 * time.Hour},
		{"24h", 24 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"30d", 30 * 24 * time.Hour},
	}

	for _, tt := range tests {
		result, err := parseRange(tt.input)
		if err != nil {
			t.Errorf("parseRange(%q) returned error: %v", tt.input, err)
		}
		if result != tt.expected {
			t.Errorf("parseRange(%q) = %v; want %v", tt.input, result, tt.expected)
		}
	}
}

func TestParseRange_Invalid(t *testing.T) {
	invalidInputs := []string{"1d", "48h", "invalid", "", "1m"}

	for _, input := range invalidInputs {
		_, err := parseRange(input)
		if err == nil {
			t.Errorf("parseRange(%q) should return error", input)
		}
	}
}

// --- checkOrigin tests ---

func TestCheckOrigin_NoOrigin(t *testing.T) {
	req := httptest.NewRequest("GET", "/ws", nil)
	// No Origin header - should pass
	if !checkOrigin(req) {
		t.Error("checkOrigin should return true when no Origin header is present")
	}
}

func TestCheckOrigin_SameOrigin(t *testing.T) {
	// Clear allowed origins for same-origin test
	oldOrigins := allowedOrigins
	allowedOrigins = nil
	defer func() { allowedOrigins = oldOrigins }()

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Host = "localhost:8080"
	req.Header.Set("Origin", "http://localhost:8080")

	if !checkOrigin(req) {
		t.Error("checkOrigin should return true for same-origin requests")
	}
}

func TestCheckOrigin_DifferentOrigin(t *testing.T) {
	// Clear allowed origins for same-origin test
	oldOrigins := allowedOrigins
	allowedOrigins = nil
	defer func() { allowedOrigins = oldOrigins }()

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Host = "localhost:8080"
	req.Header.Set("Origin", "http://evil.com")

	if checkOrigin(req) {
		t.Error("checkOrigin should return false for different origin")
	}
}

func TestCheckOrigin_AllowedOrigins(t *testing.T) {
	oldOrigins := allowedOrigins
	allowedOrigins = []string{"http://allowed.com", "https://also-allowed.com"}
	defer func() { allowedOrigins = oldOrigins }()

	tests := []struct {
		origin   string
		expected bool
	}{
		{"http://allowed.com", true},
		{"https://also-allowed.com", true},
		{"http://not-allowed.com", false},
	}

	for _, tt := range tests {
		req := httptest.NewRequest("GET", "/ws", nil)
		req.Header.Set("Origin", tt.origin)
		result := checkOrigin(req)
		if result != tt.expected {
			t.Errorf("checkOrigin with origin %q = %v; want %v", tt.origin, result, tt.expected)
		}
	}
}

// --- getEnv tests ---

func TestGetEnv_WithValue(t *testing.T) {
	t.Setenv("TEST_VAR", "test_value")
	result := getEnv("TEST_VAR", "default")
	if result != "test_value" {
		t.Errorf("getEnv = %q; want %q", result, "test_value")
	}
}

func TestGetEnv_EmptyValue(t *testing.T) {
	t.Setenv("TEST_VAR_EMPTY", "")
	result := getEnv("TEST_VAR_EMPTY", "default")
	if result != "default" {
		t.Errorf("getEnv with empty value = %q; want %q", result, "default")
	}
}

func TestGetEnv_NotSet(t *testing.T) {
	result := getEnv("NONEXISTENT_VAR_12345", "default")
	if result != "default" {
		t.Errorf("getEnv for nonexistent var = %q; want %q", result, "default")
	}
}

// --- getCurrentHourBucket tests ---

func TestGetCurrentHourBucket(t *testing.T) {
	bucket := getCurrentHourBucket()
	now := time.Now()
	expected := now.Truncate(time.Hour).Unix()

	if bucket != expected {
		t.Errorf("getCurrentHourBucket() = %d; want %d", bucket, expected)
	}

	// Verify it's aligned to hour boundary
	if bucket%3600 != 0 {
		t.Errorf("getCurrentHourBucket() = %d is not aligned to hour boundary", bucket)
	}
}

// --- incrementCounter tests ---

func TestIncrementCounter(t *testing.T) {
	m := &sync.Map{}

	// First increment creates the counter
	incrementCounter(m, "test")
	val, ok := m.Load("test")
	if !ok {
		t.Fatal("counter not created")
	}
	if val.(*atomic.Int64).Load() != 1 {
		t.Errorf("counter = %d; want 1", val.(*atomic.Int64).Load())
	}

	// Second increment increases it
	incrementCounter(m, "test")
	val, _ = m.Load("test")
	if val.(*atomic.Int64).Load() != 2 {
		t.Errorf("counter = %d; want 2", val.(*atomic.Int64).Load())
	}
}

func TestIncrementCounter_EmptyKey(t *testing.T) {
	m := &sync.Map{}
	incrementCounter(m, "")

	// Empty key should not create entry
	count := 0
	m.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("empty key created %d entries; want 0", count)
	}
}

// --- getTop5 tests ---

func TestGetTop5(t *testing.T) {
	m := &sync.Map{}

	// Add 7 items with different counts
	items := []struct {
		key   string
		count int64
	}{
		{"a", 10},
		{"b", 50},
		{"c", 30},
		{"d", 20},
		{"e", 40},
		{"f", 5},
		{"g", 15},
	}

	for _, item := range items {
		counter := &atomic.Int64{}
		counter.Store(item.count)
		m.Store(item.key, counter)
	}

	result := getTop5(m)

	if len(result) != 5 {
		t.Errorf("getTop5 returned %d items; want 5", len(result))
	}

	// Should be in descending order: b(50), e(40), c(30), d(20), g(15)
	expectedOrder := []string{"b", "e", "c", "d", "g"}
	for i, expected := range expectedOrder {
		if result[i].Name != expected {
			t.Errorf("getTop5[%d].Name = %q; want %q", i, result[i].Name, expected)
		}
	}
}

func TestGetTop5_LessThan5Items(t *testing.T) {
	m := &sync.Map{}

	counter := &atomic.Int64{}
	counter.Store(10)
	m.Store("only_one", counter)

	result := getTop5(m)

	if len(result) != 1 {
		t.Errorf("getTop5 with 1 item returned %d items; want 1", len(result))
	}
}

// --- API handler tests ---

func setupTestDB(t *testing.T) func() {
	var err error
	statsDB, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}

	schema := `
	CREATE TABLE country_stats (
		country TEXT NOT NULL,
		service TEXT NOT NULL DEFAULT 'Other',
		hour_bucket INTEGER NOT NULL,
		packet_count INTEGER NOT NULL DEFAULT 0,
		UNIQUE(country, service, hour_bucket)
	);
	CREATE TABLE asn_stats (
		asn_org TEXT NOT NULL,
		service TEXT NOT NULL DEFAULT 'Other',
		hour_bucket INTEGER NOT NULL,
		packet_count INTEGER NOT NULL DEFAULT 0,
		UNIQUE(asn_org, service, hour_bucket)
	);
	`
	if _, err := statsDB.Exec(schema); err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	return func() {
		statsDB.Close()
	}
}

func TestHandleStatsTop_Country(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Insert test data
	hourBucket := time.Now().Truncate(time.Hour).Unix()
	_, err := statsDB.Exec(
		"INSERT INTO country_stats (country, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"United States", "HTTPS", hourBucket, 100,
	)
	if err != nil {
		t.Fatalf("failed to insert test data: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/stats/top?type=country&range=1h", nil)
	w := httptest.NewRecorder()

	handleStatsTop(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want %d", w.Code, http.StatusOK)
	}

	var response TopStatsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(response.Items) != 1 {
		t.Errorf("items count = %d; want 1", len(response.Items))
	}
	if response.Items[0].Name != "United States" {
		t.Errorf("item name = %q; want %q", response.Items[0].Name, "United States")
	}
	if response.Items[0].Count != 100 {
		t.Errorf("item count = %d; want 100", response.Items[0].Count)
	}
}

func TestHandleStatsTop_InvalidType(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/stats/top?type=invalid", nil)
	w := httptest.NewRecorder()

	handleStatsTop(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleStatsTop_InvalidRange(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/stats/top?type=country&range=invalid", nil)
	w := httptest.NewRecorder()

	handleStatsTop(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleStatsTop_ServiceFilter(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	hourBucket := time.Now().Truncate(time.Hour).Unix()
	// Insert data for different services
	_, _ = statsDB.Exec(
		"INSERT INTO country_stats (country, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"Germany", "HTTPS", hourBucket, 50,
	)
	_, _ = statsDB.Exec(
		"INSERT INTO country_stats (country, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"Germany", "HTTP", hourBucket, 30,
	)

	// Filter by HTTPS only
	req := httptest.NewRequest("GET", "/api/stats/top?type=country&range=1h&service=HTTPS", nil)
	w := httptest.NewRecorder()

	handleStatsTop(w, req)

	var response TopStatsResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	if len(response.Items) != 1 {
		t.Errorf("items count = %d; want 1", len(response.Items))
	}
	if response.Items[0].Count != 50 {
		t.Errorf("item count = %d; want 50 (HTTPS only)", response.Items[0].Count)
	}
}

func TestHandleStatsTimeseries_MissingName(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/stats/timeseries?type=country&range=1h", nil)
	w := httptest.NewRecorder()

	handleStatsTimeseries(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleStatsTimeseries_ValidRequest(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	hourBucket := time.Now().Truncate(time.Hour).Unix()
	_, _ = statsDB.Exec(
		"INSERT INTO country_stats (country, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"Japan", "HTTPS", hourBucket, 75,
	)

	req := httptest.NewRequest("GET", "/api/stats/timeseries?type=country&range=1h&name=Japan", nil)
	w := httptest.NewRecorder()

	handleStatsTimeseries(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want %d", w.Code, http.StatusOK)
	}

	var response TimeSeriesResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	if response.Name != "Japan" {
		t.Errorf("name = %q; want %q", response.Name, "Japan")
	}
	if len(response.Points) != 1 {
		t.Errorf("points count = %d; want 1", len(response.Points))
	}
}

func TestHandleStatsServices(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	hourBucket := time.Now().Truncate(time.Hour).Unix()
	_, _ = statsDB.Exec(
		"INSERT INTO country_stats (country, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"France", "HTTPS", hourBucket, 100,
	)
	_, _ = statsDB.Exec(
		"INSERT INTO country_stats (country, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"France", "DNS", hourBucket, 50,
	)

	req := httptest.NewRequest("GET", "/api/stats/services?range=1h", nil)
	w := httptest.NewRecorder()

	handleStatsServices(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want %d", w.Code, http.StatusOK)
	}

	var services []ServiceCount
	json.Unmarshal(w.Body.Bytes(), &services)

	if len(services) != 2 {
		t.Errorf("services count = %d; want 2", len(services))
	}
	// Should be sorted by count descending
	if services[0].Name != "HTTPS" {
		t.Errorf("top service = %q; want HTTPS", services[0].Name)
	}
}

// --- hourlyBuffer tests ---

func TestHourlyBuffer_Add(t *testing.T) {
	// We need a mock statsDB for flush to not fail
	var err error
	statsDB, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	defer statsDB.Close()

	schema := `
	CREATE TABLE country_stats (
		country TEXT NOT NULL,
		service TEXT NOT NULL DEFAULT 'Other',
		hour_bucket INTEGER NOT NULL,
		packet_count INTEGER NOT NULL DEFAULT 0,
		UNIQUE(country, service, hour_bucket)
	);
	CREATE TABLE asn_stats (
		asn_org TEXT NOT NULL,
		service TEXT NOT NULL DEFAULT 'Other',
		hour_bucket INTEGER NOT NULL,
		packet_count INTEGER NOT NULL DEFAULT 0,
		UNIQUE(asn_org, service, hour_bucket)
	);
	`
	statsDB.Exec(schema)

	buffer := newHourlyBuffer()

	buffer.add(statsEvent{country: "US", asnOrg: "Google", service: "HTTPS"})
	buffer.add(statsEvent{country: "US", asnOrg: "Google", service: "HTTPS"})
	buffer.add(statsEvent{country: "UK", asnOrg: "Amazon", service: "HTTP"})

	buffer.Lock()
	defer buffer.Unlock()

	if buffer.countryService["US|HTTPS"] != 2 {
		t.Errorf("US|HTTPS count = %d; want 2", buffer.countryService["US|HTTPS"])
	}
	if buffer.countryService["UK|HTTP"] != 1 {
		t.Errorf("UK|HTTP count = %d; want 1", buffer.countryService["UK|HTTP"])
	}
	if buffer.asnService["Google|HTTPS"] != 2 {
		t.Errorf("Google|HTTPS count = %d; want 2", buffer.asnService["Google|HTTPS"])
	}
}

func TestHourlyBuffer_EmptyService(t *testing.T) {
	var err error
	statsDB, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	defer statsDB.Close()

	schema := `
	CREATE TABLE country_stats (
		country TEXT NOT NULL,
		service TEXT NOT NULL DEFAULT 'Other',
		hour_bucket INTEGER NOT NULL,
		packet_count INTEGER NOT NULL DEFAULT 0,
		UNIQUE(country, service, hour_bucket)
	);
	CREATE TABLE asn_stats (
		asn_org TEXT NOT NULL,
		service TEXT NOT NULL DEFAULT 'Other',
		hour_bucket INTEGER NOT NULL,
		packet_count INTEGER NOT NULL DEFAULT 0,
		UNIQUE(asn_org, service, hour_bucket)
	);
	`
	statsDB.Exec(schema)

	buffer := newHourlyBuffer()

	// Empty service should default to "Other"
	buffer.add(statsEvent{country: "CA", asnOrg: "Test", service: ""})

	buffer.Lock()
	defer buffer.Unlock()

	if buffer.countryService["CA|Other"] != 1 {
		t.Errorf("CA|Other count = %d; want 1", buffer.countryService["CA|Other"])
	}
}

// --- flushLocked tests ---

func TestHourlyBuffer_Flush(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	buffer := newHourlyBuffer()
	buffer.countryService["US|HTTPS"] = 10
	buffer.countryService["UK|HTTP"] = 5
	buffer.asnService["Google|HTTPS"] = 8
	buffer.asnService["Amazon|DNS"] = 3

	buffer.flush()

	// Verify data was written to database
	var count int
	err := statsDB.QueryRow("SELECT packet_count FROM country_stats WHERE country = 'US' AND service = 'HTTPS'").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}
	if count != 10 {
		t.Errorf("US|HTTPS in DB = %d; want 10", count)
	}

	err = statsDB.QueryRow("SELECT packet_count FROM asn_stats WHERE asn_org = 'Google' AND service = 'HTTPS'").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query asn: %v", err)
	}
	if count != 8 {
		t.Errorf("Google|HTTPS in DB = %d; want 8", count)
	}

	// Buffer should be cleared after flush
	if len(buffer.countryService) != 0 {
		t.Errorf("buffer.countryService not cleared after flush")
	}
}

func TestHourlyBuffer_FlushEmpty(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	buffer := newHourlyBuffer()
	// Flush empty buffer should not error
	buffer.flush()

	// Verify no rows were inserted
	var count int
	statsDB.QueryRow("SELECT COUNT(*) FROM country_stats").Scan(&count)
	if count != 0 {
		t.Errorf("empty flush inserted %d rows; want 0", count)
	}
}

func TestHourlyBuffer_FlushUpsert(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	hourBucket := getCurrentHourBucket()

	// Pre-insert some data
	_, err := statsDB.Exec(
		"INSERT INTO country_stats (country, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"US", "HTTPS", hourBucket, 50,
	)
	if err != nil {
		t.Fatalf("failed to pre-insert: %v", err)
	}

	// Flush more data for the same country/service/hour
	buffer := newHourlyBuffer()
	buffer.hourBucket = hourBucket
	buffer.countryService["US|HTTPS"] = 25

	buffer.flush()

	// Should be 50 + 25 = 75
	var count int
	statsDB.QueryRow("SELECT packet_count FROM country_stats WHERE country = 'US' AND service = 'HTTPS'").Scan(&count)
	if count != 75 {
		t.Errorf("upsert result = %d; want 75 (50 + 25)", count)
	}
}

// --- cleanupOldStats tests ---
// Note: cleanupOldStats uses DELETE ... LIMIT which requires SQLite compiled
// with SQLITE_ENABLE_UPDATE_DELETE_LIMIT. The modernc.org/sqlite pure-Go
// implementation doesn't support this, so we test the cleanup logic manually.

func TestCleanupOldStats_Logic(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Save original retention and set to 1 day for test
	oldRetention := statsRetentionDays
	statsRetentionDays = 1
	defer func() { statsRetentionDays = oldRetention }()

	now := time.Now()
	oldBucket := now.Add(-48 * time.Hour).Truncate(time.Hour).Unix() // 2 days ago
	newBucket := now.Truncate(time.Hour).Unix()                      // current hour

	// Insert old and new data
	statsDB.Exec("INSERT INTO country_stats (country, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"OldCountry", "HTTP", oldBucket, 100)
	statsDB.Exec("INSERT INTO country_stats (country, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"NewCountry", "HTTP", newBucket, 100)
	statsDB.Exec("INSERT INTO asn_stats (asn_org, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"OldASN", "HTTP", oldBucket, 50)
	statsDB.Exec("INSERT INTO asn_stats (asn_org, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"NewASN", "HTTP", newBucket, 50)

	// Test the cleanup cutoff calculation
	cutoff := time.Now().Add(-time.Duration(statsRetentionDays) * 24 * time.Hour).Unix()

	// Manually delete (simulating what cleanupOldStats does without LIMIT)
	statsDB.Exec("DELETE FROM country_stats WHERE hour_bucket < ?", cutoff)
	statsDB.Exec("DELETE FROM asn_stats WHERE hour_bucket < ?", cutoff)

	// Old data should be deleted
	var count int
	statsDB.QueryRow("SELECT COUNT(*) FROM country_stats WHERE country = 'OldCountry'").Scan(&count)
	if count != 0 {
		t.Errorf("old country data still exists: %d rows", count)
	}

	statsDB.QueryRow("SELECT COUNT(*) FROM asn_stats WHERE asn_org = 'OldASN'").Scan(&count)
	if count != 0 {
		t.Errorf("old ASN data still exists: %d rows", count)
	}

	// New data should remain
	statsDB.QueryRow("SELECT COUNT(*) FROM country_stats WHERE country = 'NewCountry'").Scan(&count)
	if count != 1 {
		t.Errorf("new country data missing: %d rows; want 1", count)
	}

	statsDB.QueryRow("SELECT COUNT(*) FROM asn_stats WHERE asn_org = 'NewASN'").Scan(&count)
	if count != 1 {
		t.Errorf("new ASN data missing: %d rows; want 1", count)
	}
}

// --- getPublicIP tests with mock server ---

func TestGetPublicIP_ValidIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "203.0.113.1")
	}))
	defer server.Close()

	ip, err := getPublicIP(server.URL)
	if err != nil {
		t.Fatalf("getPublicIP error: %v", err)
	}
	if ip != "203.0.113.1" {
		t.Errorf("ip = %q; want %q", ip, "203.0.113.1")
	}
}

func TestGetPublicIP_InvalidIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not-an-ip")
	}))
	defer server.Close()

	_, err := getPublicIP(server.URL)
	if err == nil {
		t.Error("getPublicIP should return error for invalid IP")
	}
}

func TestGetPublicIP_IPv6(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "2001:db8::1")
	}))
	defer server.Close()

	ip, err := getPublicIP(server.URL)
	if err != nil {
		t.Fatalf("getPublicIP error: %v", err)
	}
	if ip != "2001:db8::1" {
		t.Errorf("ip = %q; want %q", ip, "2001:db8::1")
	}
}

// --- More API handler tests ---

func TestHandleStatsTop_ASN(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	hourBucket := time.Now().Truncate(time.Hour).Unix()
	statsDB.Exec(
		"INSERT INTO asn_stats (asn_org, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"Google LLC", "HTTPS", hourBucket, 200,
	)
	statsDB.Exec(
		"INSERT INTO asn_stats (asn_org, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"Amazon.com", "HTTP", hourBucket, 150,
	)

	req := httptest.NewRequest("GET", "/api/stats/top?type=asn&range=1h", nil)
	w := httptest.NewRecorder()

	handleStatsTop(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want %d", w.Code, http.StatusOK)
	}

	var response TopStatsResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	if len(response.Items) != 2 {
		t.Errorf("items count = %d; want 2", len(response.Items))
	}
	if response.Items[0].Name != "Google LLC" {
		t.Errorf("top ASN = %q; want Google LLC", response.Items[0].Name)
	}
	if response.Type != "asn" {
		t.Errorf("type = %q; want asn", response.Type)
	}
}

func TestHandleStatsTop_Limit(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	hourBucket := time.Now().Truncate(time.Hour).Unix()
	// Insert 5 countries
	for i := 1; i <= 5; i++ {
		statsDB.Exec(
			"INSERT INTO country_stats (country, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
			fmt.Sprintf("Country%d", i), "HTTPS", hourBucket, i*10,
		)
	}

	// Request with limit=2
	req := httptest.NewRequest("GET", "/api/stats/top?type=country&range=1h&limit=2", nil)
	w := httptest.NewRecorder()

	handleStatsTop(w, req)

	var response TopStatsResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	if len(response.Items) != 2 {
		t.Errorf("items count with limit=2 = %d; want 2", len(response.Items))
	}
}

func TestHandleStatsTop_DefaultRange(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	// Request without range parameter should default to 24h
	req := httptest.NewRequest("GET", "/api/stats/top?type=country", nil)
	w := httptest.NewRecorder()

	handleStatsTop(w, req)

	var response TopStatsResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	if response.Range != "24h" {
		t.Errorf("default range = %q; want 24h", response.Range)
	}
}

func TestHandleStatsTop_EmptyResults(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/stats/top?type=country&range=1h", nil)
	w := httptest.NewRecorder()

	handleStatsTop(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want %d", w.Code, http.StatusOK)
	}

	var response TopStatsResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	// Should return empty array, not null
	if response.Items == nil {
		t.Error("items should be empty array, not nil")
	}
	if len(response.Items) != 0 {
		t.Errorf("items count = %d; want 0", len(response.Items))
	}
}

func TestHandleStatsTop_AllServicesFilter(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	hourBucket := time.Now().Truncate(time.Hour).Unix()
	statsDB.Exec("INSERT INTO country_stats (country, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"Brazil", "HTTPS", hourBucket, 30)
	statsDB.Exec("INSERT INTO country_stats (country, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"Brazil", "HTTP", hourBucket, 20)

	// service=all should aggregate all services
	req := httptest.NewRequest("GET", "/api/stats/top?type=country&range=1h&service=all", nil)
	w := httptest.NewRecorder()

	handleStatsTop(w, req)

	var response TopStatsResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	if len(response.Items) != 1 {
		t.Errorf("items count = %d; want 1", len(response.Items))
	}
	if response.Items[0].Count != 50 {
		t.Errorf("aggregated count = %d; want 50 (30+20)", response.Items[0].Count)
	}
}

func TestHandleStatsTimeseries_ASN(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	hourBucket := time.Now().Truncate(time.Hour).Unix()
	statsDB.Exec(
		"INSERT INTO asn_stats (asn_org, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"Cloudflare", "HTTPS", hourBucket, 100,
	)

	req := httptest.NewRequest("GET", "/api/stats/timeseries?type=asn&range=1h&name=Cloudflare", nil)
	w := httptest.NewRecorder()

	handleStatsTimeseries(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want %d", w.Code, http.StatusOK)
	}

	var response TimeSeriesResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	if response.Name != "Cloudflare" {
		t.Errorf("name = %q; want Cloudflare", response.Name)
	}
	if response.Type != "asn" {
		t.Errorf("type = %q; want asn", response.Type)
	}
}

func TestHandleStatsTimeseries_InvalidType(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/stats/timeseries?type=invalid&range=1h&name=Test", nil)
	w := httptest.NewRecorder()

	handleStatsTimeseries(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleStatsTimeseries_InvalidRange(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/stats/timeseries?type=country&range=invalid&name=Test", nil)
	w := httptest.NewRecorder()

	handleStatsTimeseries(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleStatsTimeseries_WithServiceFilter(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	hourBucket := time.Now().Truncate(time.Hour).Unix()
	statsDB.Exec("INSERT INTO country_stats (country, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"India", "HTTPS", hourBucket, 80)
	statsDB.Exec("INSERT INTO country_stats (country, service, hour_bucket, packet_count) VALUES (?, ?, ?, ?)",
		"India", "HTTP", hourBucket, 40)

	// Filter by HTTPS only
	req := httptest.NewRequest("GET", "/api/stats/timeseries?type=country&range=1h&name=India&service=HTTPS", nil)
	w := httptest.NewRecorder()

	handleStatsTimeseries(w, req)

	var response TimeSeriesResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	if len(response.Points) != 1 {
		t.Errorf("points count = %d; want 1", len(response.Points))
	}
	if response.Points[0].Count != 80 {
		t.Errorf("HTTPS-filtered count = %d; want 80", response.Points[0].Count)
	}
}

func TestHandleStatsTimeseries_EmptyResults(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/stats/timeseries?type=country&range=1h&name=NonExistent", nil)
	w := httptest.NewRecorder()

	handleStatsTimeseries(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want %d", w.Code, http.StatusOK)
	}

	var response TimeSeriesResponse
	json.Unmarshal(w.Body.Bytes(), &response)

	if response.Points == nil {
		t.Error("points should be empty array, not nil")
	}
}

func TestHandleStatsServices_InvalidRange(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/stats/services?range=invalid", nil)
	w := httptest.NewRecorder()

	handleStatsServices(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleStatsServices_EmptyResults(t *testing.T) {
	cleanup := setupTestDB(t)
	defer cleanup()

	req := httptest.NewRequest("GET", "/api/stats/services?range=1h", nil)
	w := httptest.NewRecorder()

	handleStatsServices(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d; want %d", w.Code, http.StatusOK)
	}

	var services []ServiceCount
	json.Unmarshal(w.Body.Bytes(), &services)

	if services == nil {
		t.Error("services should be empty array, not nil")
	}
}

// --- broadcast tests ---

func TestBroadcast_NoClients(t *testing.T) {
	// Clear any existing clients
	clientsLock.Lock()
	clients = make(map[*Client]bool)
	clientsLock.Unlock()

	// Broadcasting to no clients should not panic
	msg := WebSocketMessage{Type: "test", Data: "hello"}
	broadcast(msg) // Should not panic
}

func TestBroadcast_WithClients(t *testing.T) {
	// Set up a mock client with a buffered channel
	clientsLock.Lock()
	clients = make(map[*Client]bool)
	mockClient := &Client{
		conn: nil, // We won't actually use the connection
		send: make(chan WebSocketMessage, 10),
	}
	clients[mockClient] = true
	clientsLock.Unlock()

	defer func() {
		clientsLock.Lock()
		delete(clients, mockClient)
		clientsLock.Unlock()
	}()

	msg := WebSocketMessage{Type: "geo", Data: map[string]string{"test": "data"}}
	broadcast(msg)

	// Check if message was sent to the channel
	select {
	case received := <-mockClient.send:
		if received.Type != "geo" {
			t.Errorf("received type = %q; want geo", received.Type)
		}
	default:
		t.Error("message was not sent to client channel")
	}
}

func TestBroadcast_FullBuffer(t *testing.T) {
	// Set up a client with a full buffer
	clientsLock.Lock()
	clients = make(map[*Client]bool)
	mockClient := &Client{
		conn: nil,
		send: make(chan WebSocketMessage, 1), // Small buffer
	}
	// Fill the buffer
	mockClient.send <- WebSocketMessage{Type: "filler"}
	clients[mockClient] = true
	clientsLock.Unlock()

	defer func() {
		clientsLock.Lock()
		delete(clients, mockClient)
		clientsLock.Unlock()
	}()

	// This should not block even though buffer is full
	msg := WebSocketMessage{Type: "test"}
	broadcast(msg) // Should not panic or block
}

// --- checkOrigin edge cases ---

func TestCheckOrigin_HTTPSOrigin(t *testing.T) {
	oldOrigins := allowedOrigins
	allowedOrigins = nil
	defer func() { allowedOrigins = oldOrigins }()

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Host = "example.com"
	req.Header.Set("Origin", "https://example.com")

	if !checkOrigin(req) {
		t.Error("checkOrigin should return true for HTTPS same-origin")
	}
}

// --- getTop5 edge cases ---

func TestGetTop5_EmptyMap(t *testing.T) {
	m := &sync.Map{}
	result := getTop5(m)

	// getTop5 returns nil for empty map, which is fine since callers
	// (like the API handlers) convert nil to empty slice before JSON encoding
	if len(result) != 0 {
		t.Errorf("getTop5 of empty map = %d items; want 0", len(result))
	}
}

// --- Concurrent incrementCounter test ---

func TestIncrementCounter_Concurrent(t *testing.T) {
	m := &sync.Map{}
	const goroutines = 100
	const incrementsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				incrementCounter(m, "concurrent_key")
			}
		}()
	}

	wg.Wait()

	val, ok := m.Load("concurrent_key")
	if !ok {
		t.Fatal("counter not found")
	}

	expected := int64(goroutines * incrementsPerGoroutine)
	actual := val.(*atomic.Int64).Load()
	if actual != expected {
		t.Errorf("concurrent counter = %d; want %d", actual, expected)
	}
}
