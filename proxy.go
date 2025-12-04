package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
)

// Daftar 50 website penyedia proxy gratis
var proxyWebsites = []string{
	"https://www.sslproxies.org/",
	"https://free-proxy-list.net/",
	"https://www.us-proxy.org/",
	"https://www.socks-proxy.net/",
	"https://free-proxy-list.net/anonymous-proxy.html",
	"https://www.proxy-list.download/HTTP",
	"https://www.proxy-list.download/HTTPS",
	"https://www.proxy-list.download/SOCKS4",
	"https://www.proxy-list.download/SOCKS5",
	"https://spys.one/free-proxy-list/",
	"https://www.proxyscan.io/",
	"https://www.proxyhub.me/",
	"https://www.freeproxy.world/",
	"https://www.proxynova.com/proxy-server-list/",
	"https://www.kuaidaili.com/free/",
	"https://www.proxy-list.download/api/v1/get?type=http",
	"https://api.proxyscrape.com/?request=getproxies&proxytype=http",
	"https://api.proxyscrape.com/v2/?request=getproxies&protocol=http",
	"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
	"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
	"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
	"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
	"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
	"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
	"https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",
	"https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
	"https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
	"https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
	"https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
	"https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt",
	"https://www.proxygather.com/proxy-list",
	"https://www.proxydocker.com/en/proxylist/",
	"https://premproxy.com/list/",
	"https://www.my-proxy.com/free-proxy-list.html",
	"https://www.cybersyndrome.net/pla.html",
	"https://www.aliveproxy.com/",
	"https://www.proxy4free.com/",
	"https://www.vipsocks24.net/",
	"https://www.socks24.org/",
	"https://www.socks-proxy.net/",
	"https://www.proxy-list.org/english/index.php",
	"https://www.proxyfish.com/",
	"https://www.proxyservers.pro/",
	"https://www.proxyrotator.com/free-proxy-list/",
	"https://www.proxy-ninja.com/",
	"https://www.proxybazaar.com/",
	"https://www.proxybazaar.com/socks-proxies/",
	"https://www.proxybazaar.com/https-proxies/",
	"https://www.proxybazaar.com/socks4-proxies/",
	"https://www.proxybazaar.com/socks5-proxies/",
}

var proxyRegex = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b`)

func main() {
	fmt.Println("🚀 Memulai scraping proxy dari 50 sumber...")
	startTime := time.Now()

	proxies := make(chan string)
	var wg sync.WaitGroup
	uniqueProxies := make(map[string]bool)

	// Goroutine untuk menangani hasil proxy
	go func() {
		for proxy := range proxies {
			if !uniqueProxies[proxy] {
				uniqueProxies[proxy] = true
			}
		}
	}()

	// Scraping semua website secara paralel
	for _, url := range proxyWebsites {
		wg.Add(1)
		go scrapeWebsite(url, proxies, &wg)
	}

	wg.Wait()
	close(proxies)

	// Menyimpan ke file
	saveToFile(uniqueProxies)

	fmt.Printf("\n✅ Selesai! %d proxy unik ditemukan dan disimpan dalam %.2f detik\n", 
		len(uniqueProxies), time.Since(startTime).Seconds())
}

func scrapeWebsite(url string, proxies chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	fmt.Printf("🔍 Scraping: %s\n", url)

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("❌ Gagal: %s - %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("⚠️ Status %d: %s\n", resp.StatusCode, url)
		return
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		matches := proxyRegex.FindAllString(line, -1)
		for _, match := range matches {
			proxies <- match
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("⚠️ Error membaca: %s - %v\n", url, err)
	}
}

func saveToFile(proxies map[string]bool) {
	file, err := os.Create("proxy.txt")
	if err != nil {
		fmt.Printf("❌ Gagal membuat file: %v\n", err)
		return
	}
	defer file.Close()

	count := 0
	for proxy := range proxies {
		_, err := file.WriteString(proxy + "\n")
		if err != nil {
			fmt.Printf("⚠️ Gagal menulis proxy: %v\n", err)
			continue
		}
		count++
	}

	fmt.Printf("💾 Disimpan %d proxy ke proxy.txt\n", count)
}
