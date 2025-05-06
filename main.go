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

	"github.com/playwright-community/playwright-go"
)

type patternDef struct {
	Name  string `json:"name"`
	Regex string `json:"value"`
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/14.1.1 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/90.0.4430.93 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
}

// ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
//     [^"'/]{1,}\.                        # Match a domainname (any character + dot)
//     [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
// "jsleak-linkfinder1": "(?:\"|')?(([a-zA-Z]{1,10}:\\/\\/|\\/\\/)[^\"'\\/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})(?:\"|')?",

// ((?:/|\.\./|\./)                    # Start with /,../,./
// [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
// [^"'><,;|()]{1,})                   # Rest of the characters can't be
// "jsleak-linkfinder2": "(?:\"|')?((?:\\/|\\.\\.\\/|\\.\\/)[^\"'><,;| *()(%%$^\\/\\\\\\[\\]][^\"'><,;|()]{1,})(?:\"|')?",

// ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
//     [a-zA-Z0-9_\-/.]{1,}                # Resource name
//     \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
//     (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
// "jsleak-linkfinder3": "(?:\"|')?([a-zA-Z0-9_\\-\\/]{1,}\\/[a-zA-Z0-9_\\-\\/.]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|#][^\"|']{0,}|))(?:\"|')?"

// ([a-zA-Z0-9_\-/]{1,}/               # REST API (no extension) with /
// [a-zA-Z0-9_\-/]{3,}                 # Proper REST endpoints usually have 3+ chars
// (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
// "jsleak-linkfinder4": "(?:\"|')?([a-zA-Z0-9_\\-\\/]{1,}\\/[a-zA-Z0-9_\\-\\/]{3,}([\\?|#][^\"|']{0,}|))(?:\"|')?"

// ([a-zA-Z0-9_\-]{1,}                 # filename
//     \.(?:php|asp|aspx|jsp|json|
//          action|html|js|txt|xml)        # . + extension
//     (?:[\?|#][^"|']{0,}|))              # ? or # mark with parameters
// "jsleak-linkfinder5": "(?:\"|')?([a-zA-Z0-9_\\-]{1,}\\.(php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\\?|#][^\"|']{0,}|))(?:\"|')?"

var internalJSON = `{
	"jsleak-linkfinder": "(?:\"|')?(([a-zA-Z]{1,10}:\\/\\/|\\/\\/)[^\"'\\/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:\\/|\\.\\.\\/|\\.\\/)[^\"'><,;| *()(%%$^\\/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-\\/]{1,}\\/[a-zA-Z0-9_\\-\\/.]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\\-\\/]{1,}\\/[a-zA-Z0-9_\\-\\/]{3,}([\\?|#][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\\?|#][^\"|']{0,}|))(?:\"|')?",
	"uri1": "(https?:\\/\\/|\\/\\/)([a-zA-Z0-9\\-_\\.@]{3,256})?(\\/[^\\s\"'<>]*)?",
	"uri2": "[a-zA-Z]{3,10}://([a-zA-Z0-9\\-_\\.@]{3,256})?(\\/[^\\s\"'<>]*)?",
	"password_in_url": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
	"amazon1": "//s3-[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9._-]+",
	"amazon2": "//s3\\.amazonaws\\.com/[a-z0-9._-]+",
	"amazon3": "[a-z0-9.-]+\\.s3-[a-z0-9-]\\.amazonaws\\.com",
	"amazon4": "[a-z0-9.-]+\\.s3-website[.-](eu|ap|us|ca|sa|cn)",
	"amazon5": "[a-z0-9.-]+\\.s3\\.amazonaws\\.com",
	"amazon6": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
	"firebase1": "[a-z0-9.-]+\\.firebaseio\\.com",
	"firebase2": "[a-z0-9.-]+\\.firebaseapp\\.com",
	"grafanaserviceaccount2": "([a-zA-Z0-9-]+\\.grafana\\.net)",
	"azurewebsites1": "([a-z0-9-]+(\\.[a-z0-9-]+)*\\.(azurewebsites\\.net))",
	"azurefunctionkey": "(https?:\\/\\/|\\/\\/)?([a-zA-Z0-9-]{2,30})\\.azurewebsites\\.net\\/api\\/([a-zA-Z0-9-]{2,30})",
	"azurecontainerregistry1": "([a-zA-Z0-9-]{1,100})\\.azurecr\\.io",
	"artifactory2": "([A-Za-z0-9]([A-Za-z0-9\\-]{0,61}[A-Za-z0-9])\\.jfrog\\.io)",
	"salesforce2": "(https?:\\/\\/|\\/\\/)?[0-9a-zA-Z-\\.]{1,100}\\.my\\.salesforce\\.com",
	"databrickstoken1": "([a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.(cloud\\.databricks\\.com|gcp\\.databricks\\.com|azurewebsites\\.net))"
}`

func parseInternalJSON() []patternDef {
	var raw map[string]string
	var patterns []patternDef
	if err := json.Unmarshal([]byte(internalJSON), &raw); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse internal JSON: %v\n", err)
		return nil
	}
	patterns = make([]patternDef, 0, len(raw))
	for k, v := range raw {
		patterns = append(patterns, patternDef{
			Name:  k,
			Regex: v,
		})
	}
	return patterns
}

func loadPatternsFromJSON(filePath string) []patternDef {
	file, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read JSON file: %v\n", err)
		return nil
	}
	var raw map[string]string
	if err := json.Unmarshal(file, &raw); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse JSON file: %v\n", err)
		return nil
	}
	var patterns []patternDef
	for k, v := range raw {
		patterns = append(patterns, patternDef{
			Name:  k,
			Regex: v,
		})
	}
	return patterns
}

func getRenderedContentWithPlaywright(fullurl string, header string, timeout time.Duration) (string, error) {
	pw, err := playwright.Run()
	if err != nil {
		return "", fmt.Errorf("could not launch playwright: %v", err)
	}
	defer pw.Stop()

	// Launch the browser with headless mode
	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
	})
	if err != nil {
		return "", fmt.Errorf("could not launch browser: %v", err)
	}
	defer browser.Close()

	// Create a new page
	page, err := browser.NewPage(playwright.BrowserNewPageOptions{})
	if err != nil {
		return "", fmt.Errorf("could not create page: %v", err)
	}

	// Set custom header if provided
	if header != "" {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			page.SetExtraHTTPHeaders(map[string]string{
				strings.TrimSpace(parts[0]): strings.TrimSpace(parts[1]),
			})
		}
	}

	// Navigate to the URL with timeout and wait until network is idle
	_, err = page.Goto(fullurl, playwright.PageGotoOptions{
		Timeout:   playwright.Float(float64(timeout.Milliseconds())),
		WaitUntil: playwright.WaitUntilStateNetworkidle,
	})
	if err != nil {
		return "", fmt.Errorf("could not navigate to page: %v", err)
	}

	// Get the rendered content of the page
	content, err := page.Content()
	if err != nil {
		return "", fmt.Errorf("could not get page content: %v", err)
	}

	fmt.Println(content)

	return content, nil
}

func request(fullurl, header string, timeout time.Duration) (string, *http.Response) {
	ua := userAgents[rand.Intn(len(userAgents))]

	t := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: t,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", fullurl, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request error: %v\n", err)
		return "", nil
	}
	if header != "" {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			req.Header.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	req.Header.Set("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		return "", nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed reading body: %v\n", err)
		return "", resp
	}
	// print(string(body))
	return string(body), resp
}

func regexGrep(content string, baseURL string, patterns []patternDef, resolvePath bool) []string {
	found := make(map[string]struct{})
	var result []string
	for _, p := range patterns {
		r := regexp.MustCompile(p.Regex)
		//fmt.Println(content)
		// fmt.Println("Regex: ", r.String())
		matches := r.FindAllString(content, -1)
		//fmt.Println(matches)
		for _, m := range matches {
			// Sanitize match and replace all "
			// If "https:// is not seen as absolute url in the if below
			m = strings.ReplaceAll(m, "\"", "")

			if _, seen := found[m]; !seen {
				if resolvePath && !strings.HasPrefix(m, "http://") && !strings.HasPrefix(m, "https://") && !strings.HasPrefix(m, "//") {
					if strings.HasPrefix(m, "/") {
						fmt.Printf("%s%s\n", baseURL, m)
					} else {
						fmt.Printf("%s/%s\n", baseURL, m)
					}

				} else {
					fmt.Println(m)
				}
				found[m] = struct{}{}
				result = append(result, m)
			}
		}
	}
	return result
}

func main() {
	var timeout int
	var jsonFilePath string
	var header string
	var checkStatus bool
	var concurrency int
	var input string
	var resolvePath bool
	var noHeadlessMode bool

	flag.IntVar(&timeout, "timeout", 7, "Timeout in seconds for HTTP requests")
	flag.StringVar(&jsonFilePath, "json", "", "Path to JSON file containing additional regex patterns")
	flag.StringVar(&header, "H", "User-Agent: Chrome", "Custom header, e.g., -H 'User-Agent: xyz'")
	flag.BoolVar(&checkStatus, "checkstatus", false, "Check and print HTTP status of discovered links")
	flag.IntVar(&concurrency, "c", 3, "Concurrency level (default 3)")
	flag.StringVar(&input, "u", "", "URL or file path to process")
	flag.BoolVar(&resolvePath, "r", false, "Resolve relative paths against base URL")
	flag.BoolVar(&noHeadlessMode, "noheadless", false, "Disables headless mode")
	flag.Parse()

	allPatterns := parseInternalJSON()
	if jsonFilePath != "" {
		// append
		//allPatterns = append(allPatterns, loadPatternsFromJSON(jsonFilePath)...)
		// We want to replace the whole file
		allPatterns = loadPatternsFromJSON(jsonFilePath)
	}

	urlList := make(chan string, concurrency)
	go func() {
		if fileInfo, err := os.Stat(input); err == nil && !fileInfo.IsDir() {
			f, err := os.Open(input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to open file: %v\n", err)
				close(urlList)
				return
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				urlList <- scanner.Text()
			}
			f.Close()
			close(urlList)
		} else {
			urlList <- input
			close(urlList)
		}
	}()

	wg := sync.WaitGroup{}
	var content = ""
	var err error

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for inputURL := range urlList {

				if noHeadlessMode {
					content, _ = request(inputURL, header, time.Duration(timeout)*time.Second)
				} else {
					content, err = getRenderedContentWithPlaywright(inputURL, header, time.Duration(timeout)*time.Second)
					if err != nil {
						fmt.Fprintf(os.Stderr, "playwright error: %v\n", err)
						continue
					}
				}
				matches := regexGrep(content, inputURL, allPatterns, resolvePath)
				if checkStatus {
					for _, m := range matches {
						u, err := url.Parse(m)
						if err != nil {
							continue
						}
						if !u.IsAbs() {
							base, err := url.Parse(inputURL)
							if err != nil {
								continue
							}
							u = base.ResolveReference(u)
						}
						_, resp := request(u.String(), header, time.Duration(timeout)*time.Second)
						if resp != nil {
							fmt.Printf("[Status] %s -> %d\n", u.String(), resp.StatusCode)
						}
					}
				}
			}
		}()
	}
	wg.Wait()
}
