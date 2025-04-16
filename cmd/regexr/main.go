package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type patternDef struct {
	Name     string `json:"name"`
	Regex    string `json:"value"`
	Severity string `json:"severity"`
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/14.1.1 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/90.0.4430.93 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
}

func createHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: time.Second,
			}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func request(fullurl string, httpClient *http.Client, headers http.Header) string {
	req, err := http.NewRequest("GET", fullurl, nil)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	rand.Seed(time.Now().UnixNano())
	req.Header.Add("User-Agent", userAgents[rand.Intn(len(userAgents))])
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return string(bodyBytes)
}

func regexGrep(content string, baseUrl string, patterns []patternDef, checkStatus bool, httpClient *http.Client, headers http.Header) {
	base, _ := url.Parse(baseUrl)

	for _, p := range patterns {
		r := regexp.MustCompile(p.Regex)
		matches := r.FindAllString(content, -1)
		for _, v := range matches {
			link := strings.Trim(v, `""'`)
			resolvedURL, err := url.Parse(link)
			if err != nil {
				continue
			}
			finalURL := base.ResolveReference(resolvedURL).String()
			if checkStatus {
				statusCode := getStatus(finalURL, httpClient, headers)
				fmt.Printf("[+] Found [%s] [%s] [%s] - Status: %d\n", p.Name, link, baseUrl, statusCode)
			} else {
				fmt.Printf("[+] Found [%s] [%s] [%s]\n", p.Name, link, baseUrl)
			}
		}
	}
}

func getStatus(link string, httpClient *http.Client, headers http.Header) int {
	req, err := http.NewRequest("GET", link, nil)
	if err != nil {
		return 0
	}
	rand.Seed(time.Now().UnixNano())
	req.Header.Add("User-Agent", userAgents[rand.Intn(len(userAgents))])
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func main() {
	var concurrency int
	var checkStatus bool
	var jsonFilePath string
	var timeoutSeconds int
	var headersFlag headerFlags

	flag.BoolVar(&checkStatus, "k", false, "Check status codes for found links")
	flag.IntVar(&concurrency, "c", 10, "Number of concurrent workers")
	flag.StringVar(&jsonFilePath, "t", "", "Path to JSON file containing regex patterns")
	flag.IntVar(&timeoutSeconds, "timeout", 10, "Timeout in seconds for HTTP requests")
	flag.Var(&headersFlag, "H", "Custom headers, e.g. -H 'User-Agent: custom' (can be repeated)")
	flag.Parse()

	headers := make(http.Header)
	for _, h := range headersFlag {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			headers.Add(key, value)
		}
	}

	var patterns []patternDef
	if jsonFilePath != "" {
		loadedPatterns, err := loadPatternsFromJSON(jsonFilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading JSON patterns: %v\n", err)
			os.Exit(1)
		}
		patterns = loadedPatterns
	}

	httpClient := createHTTPClient(time.Duration(timeoutSeconds) * time.Second)

	urls := make(chan string, concurrency)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			urls <- sc.Text()
		}
		close(urls)
		if err := sc.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		}
	}()

	wg := sync.WaitGroup{}
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for vUrl := range urls {
				res := request(vUrl, httpClient, headers)
				regexGrep(res, vUrl, patterns, checkStatus, httpClient, headers)
			}
		}()
	}
	wg.Wait()
}

type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func loadPatternsFromJSON(filePath string) ([]patternDef, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var patterns []patternDef
	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&patterns); err != nil {
		return nil, err
	}
	return patterns, nil
}
