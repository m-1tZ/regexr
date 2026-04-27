package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/playwright-community/playwright-go"
	"golang.org/x/term"
)

type patternDef struct {
	Name     string
	Compiled *regexp.Regexp
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/14.1.1 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/90.0.4430.93 Safari/537.36",
	"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
}

var version = "v0.2.0"

type contentTypeFilterPreset struct {
	BlockedPrefixes []string
	BlockedExact    map[string]struct{}
	BlockedResource map[string]struct{}
}

var headlessContentTypeFilterPresets = map[string]contentTypeFilterPreset{
	"off": {
		BlockedPrefixes: nil,
		BlockedExact:    map[string]struct{}{},
		BlockedResource: map[string]struct{}{},
	},
	"drop-binary": {
		BlockedPrefixes: []string{
			"image/",
			"audio/",
			"video/",
			"font/",
		},
		BlockedExact: map[string]struct{}{
			"application/octet-stream":                      {},
			"application/pdf":                               {},
			"application/zip":                               {},
			"application/gzip":                              {},
			"application/x-gzip":                            {},
			"application/x-rar-compressed":                  {},
			"application/x-7z-compressed":                   {},
			"application/vnd.microsoft.portable-executable": {},
		},
		BlockedResource: map[string]struct{}{
			"image":     {},
			"media":     {},
			"font":      {},
			"texttrack": {},
		},
	},
}

func shouldAbortHeadlessRequest(req playwright.Request, presetName string) bool {
	preset, ok := headlessContentTypeFilterPresets[presetName]
	if !ok {
		preset = headlessContentTypeFilterPresets["drop-binary"]
	}
	if len(preset.BlockedResource) == 0 {
		return false
	}

	u := strings.ToLower(req.URL())
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return false
	}

	resourceType := strings.ToLower(req.ResourceType())
	_, blocked := preset.BlockedResource[resourceType]
	return blocked
}

func shouldSkipHeadlessContent(contentTypeHeader, presetName string) bool {
	preset, ok := headlessContentTypeFilterPresets[presetName]
	if !ok {
		preset = headlessContentTypeFilterPresets["drop-binary"]
	}
	if len(preset.BlockedPrefixes) == 0 && len(preset.BlockedExact) == 0 {
		return false
	}

	ct := strings.TrimSpace(strings.ToLower(contentTypeHeader))
	if ct == "" {
		return false
	}

	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mediaType = ct
	}

	if _, blocked := preset.BlockedExact[mediaType]; blocked {
		return true
	}
	for _, prefix := range preset.BlockedPrefixes {
		if strings.HasPrefix(mediaType, prefix) {
			return true
		}
	}
	return false
}

func progressSnapshot(processed, total int64, startTime time.Time) (time.Duration, string) {
	elapsed := time.Since(startTime).Round(time.Second)
	if processed <= 0 || total <= 0 {
		return elapsed, "?"
	}
	if processed >= total {
		return elapsed, "0s"
	}
	rate := float64(processed) / time.Since(startTime).Seconds()
	if rate <= 0 {
		return elapsed, "?"
	}
	remaining := float64(total-processed) / rate
	if remaining < 0 {
		remaining = 0
	}
	return elapsed, time.Duration(remaining * float64(time.Second)).Round(time.Second).String()
}

func printLiveStats(processed, total int64, startTime time.Time, headlessEnabled bool, headlessContentFilter string, filterStats *headlessFilterStats) {
	elapsed, eta := progressSnapshot(processed, total, startTime)
	fmt.Fprintf(os.Stderr, "\n[*] live stats | %d/%d urls | uptime: %s | eta: %s\n", processed, total, elapsed, eta)
	if headlessEnabled && headlessContentFilter != "off" && filterStats != nil {
		fmt.Fprintf(os.Stderr, "[*] headless filter stats | dropped requests: %d | skipped page bodies: %d\n",
			filterStats.droppedRequests.Load(), filterStats.skippedPages.Load())
	}
}

func startInteractiveStats(statusDone <-chan struct{}, processed *atomic.Int64, total int64, startTime time.Time, headlessEnabled bool, headlessContentFilter string, filterStats *headlessFilterStats) func() {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return func() {}
	}
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return func() {}
	}

	var once sync.Once
	restore := func() {
		once.Do(func() {
			_ = term.Restore(fd, oldState)
			fmt.Fprintln(os.Stderr)
		})
	}

	fmt.Fprintln(os.Stderr, "[*] interactive mode: press 's' for live stats")

	go func() {
		defer restore()
		reader := bufio.NewReader(os.Stdin)
		for {
			select {
			case <-statusDone:
				return
			default:
			}

			b, err := reader.ReadByte()
			if err != nil {
				return
			}
			if b == 's' || b == 'S' {
				printLiveStats(processed.Load(), total, startTime, headlessEnabled, headlessContentFilter, filterStats)
			}
		}
	}()

	return restore
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
// "jsleak-linkfinder3": "(?:\"|')?([a-zA-Z0-9_\\-\\/]{1,}\\/[a-zA-Z0-9_\\-\\/.]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|#][^\"|']{0,}|))(?:\"|')?",

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
	"jsleak-linkfinder1": "(?:\"|')?(([a-zA-Z]{1,10}:\\/\\/|\\/\\/)[^\"'\\/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})(?:\"|')?",
	"jsleak-linkfinder3": "(?:\"|')?([a-zA-Z0-9_\\-\\/]{1,}\\/[a-zA-Z0-9_\\-\\/.]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|#][^\"|']{0,}|))(?:\"|')?",
	"jsleak-linkfinder4": "(?:\"|')?([a-zA-Z0-9_\\-\\/]{1,}\\/[a-zA-Z0-9_\\-\\/]{3,}([\\?|#][^\"|']{0,}|))(?:\"|')?",
	"jsleak-linkfinder5": "(?:\"|')?([a-zA-Z0-9_\\-]{1,}\\.(php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\\?|#][^\"|']{0,}|))(?:\"|')?",
	"pathfinder": "(?:\"|')((?:\\/|\\.\\.\\/|\\.\\/)[^\"'><,;|()\\s]+)(?:\"|')",
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
	"databrickstoken1": "([a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.(cloud\\.databricks\\.com|gcp\\.databricks\\.com|azurewebsites\\.net))",
	"jsdelivr":"(https?:\\/\\/|\\/\\/)cdn\\.jsdelivr\\.net\\/(npm|gh)\\/[^@\"<>\\?\\\\'\\s]+@?[^@\"<>\\?\\\\'\\s]+",
	"unpkg":"(https?:\\/\\/|\\/\\/)unpkg\\.com\\/[^@\"<>\\?\\\\'\\s]+@?[^@\"<>\\?\\\\'\\s]+"
}`

func parseInternalJSON() []patternDef {
	var raw map[string]string
	if err := json.Unmarshal([]byte(internalJSON), &raw); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse internal JSON: %v\n", err)
		return nil
	}
	patterns := make([]patternDef, 0, len(raw))
	for k, v := range raw {
		r, err := regexp.Compile(v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping pattern %q: invalid regex: %v\n", k, err)
			continue
		}
		patterns = append(patterns, patternDef{Name: k, Compiled: r})
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
	patterns := make([]patternDef, 0, len(raw))
	for k, v := range raw {
		r, err := regexp.Compile(v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping pattern %q: invalid regex: %v\n", k, err)
			continue
		}
		patterns = append(patterns, patternDef{Name: k, Compiled: r})
	}
	return patterns
}

// loadSubstringsFromFile reads a newline-delimited text file where each line
// is a plain substring to match (not a regex). Empty lines and lines starting
// with # are ignored.
func loadSubstringsFromFile(filePath string) []string {
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open substrings file: %v\n", err)
		return nil
	}
	defer f.Close()

	var substrings []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		substrings = append(substrings, line)
	}
	return substrings
}

// substringGrep searches content for each plain substring and prints the
// matching line (similar output style to regexGrep). Already-seen matches
// are deduplicated. Returns matched substrings so checkStatus can reuse them.
func substringGrep(content string, baseURL string, substrings []string, matchInformation bool) []string {
	found := make(map[string]struct{})
	var result []string

	for _, sub := range substrings {
		idx := 0
		for {
			pos := strings.Index(content[idx:], sub)
			if pos == -1 {
				break
			}
			absPos := idx + pos

			// Use the matched substring itself as the dedup key
			if _, seen := found[sub]; !seen {
				// Extra match information
				if matchInformation {
					var surroundingChars = 70

					snippetStart := absPos - surroundingChars
					if snippetStart < 0 {
						snippetStart = 0
					}
					snippetEnd := absPos + len(sub) + surroundingChars
					if snippetEnd > len(content) {
						snippetEnd = len(content)
					}
					snippet := content[snippetStart:snippetEnd]

					// Add markers if truncated
					if snippetStart > 0 {
						snippet = "..." + snippet
					}
					if snippetEnd < len(content) {
						snippet = snippet + "..."
					}

					fmt.Printf("[Match Info] [%s] [%s] [%q]\n", sub, baseURL, snippet)
				}

				found[sub] = struct{}{}
				result = append(result, sub)
			}
			// Advance past this occurrence to find further ones (all deduped anyway)
			idx = absPos + len(sub)
		}
	}
	return result
}

// browserWorker owns a single Chromium browser process and reuses it across
// multiple URL fetches. Each fetch opens a fresh context+page (tab) and closes
// it afterwards. When the configured request count or runtime limit is reached
// the browser is killed and a new one is launched transparently.
type browserWorker struct {
	pm          *playwrightManager
	stats       *headlessFilterStats
	browser     playwright.Browser
	reqCount    int
	startTime   time.Time
	maxRequests int           // 0 = unlimited
	maxRuntime  time.Duration // 0 = unlimited
}

type headlessFilterStats struct {
	droppedRequests atomic.Int64
	skippedPages    atomic.Int64
}

type playwrightManager struct {
	mu          sync.RWMutex
	pw          *playwright.Playwright
	startTime   time.Time
	launches    int
	maxLaunches int
	maxRuntime  time.Duration
}

var launchGate = make(chan struct{}, 1)

func withLaunchGate(fn func() error) error {
	launchGate <- struct{}{}
	defer func() { <-launchGate }()
	return fn()
}

func newPlaywrightManager(maxLaunches int, maxRuntime time.Duration) (*playwrightManager, error) {
	pm := &playwrightManager{
		maxLaunches: maxLaunches,
		maxRuntime:  maxRuntime,
	}
	if err := pm.startLocked(); err != nil {
		return nil, err
	}
	return pm, nil
}

func (pm *playwrightManager) startLocked() error {
	pw, err := playwright.Run()
	if err != nil {
		return err
	}
	pm.pw = pw
	pm.startTime = time.Now()
	pm.launches = 0
	return nil
}

func (pm *playwrightManager) stop() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.pw != nil {
		pm.pw.Stop()
		pm.pw = nil
	}
}

func (pm *playwrightManager) maybeRestartLocked() error {
	restartByLaunches := pm.maxLaunches > 0 && pm.launches >= pm.maxLaunches
	restartByRuntime := pm.maxRuntime > 0 && time.Since(pm.startTime) >= pm.maxRuntime
	if !restartByLaunches && !restartByRuntime {
		return nil
	}

	if pm.pw != nil {
		pm.pw.Stop()
		pm.pw = nil
	}
	return pm.startLocked()
}

func (pm *playwrightManager) launchBrowser() (playwright.Browser, error) {
	var browser playwright.Browser
	err := withLaunchGate(func() error {
		pm.mu.Lock()
		defer pm.mu.Unlock()

		if err := pm.maybeRestartLocked(); err != nil {
			return fmt.Errorf("could not restart playwright: %v", err)
		}
		if pm.pw == nil {
			return fmt.Errorf("playwright process is not running")
		}

		launched, err := pm.pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
			Headless: playwright.Bool(true),
			Args: []string{
				"--disable-dev-shm-usage",
			},
		})
		if err != nil {
			return err
		}
		browser = launched
		pm.launches++
		return nil
	})
	if err != nil {
		return nil, err
	}
	return browser, nil
}

func newBrowserWorker(pm *playwrightManager, stats *headlessFilterStats, maxRequests int, maxRuntime time.Duration) (*browserWorker, error) {
	bw := &browserWorker{
		pm:          pm,
		stats:       stats,
		maxRequests: maxRequests,
		maxRuntime:  maxRuntime,
	}
	if err := bw.launch(); err != nil {
		return nil, err
	}
	return bw, nil
}

func (bw *browserWorker) launch() error {
	const maxAttempts = 5

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		browser, err := bw.pm.launchBrowser()
		if err == nil {
			bw.browser = browser
			bw.reqCount = 0
			bw.startTime = time.Now()
			return nil
		}

		lastErr = err
		if attempt == maxAttempts {
			break
		}

		backoff := time.Duration(1<<(attempt-1)) * time.Second
		jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
		time.Sleep(backoff + jitter)
	}

	return fmt.Errorf("could not launch browser after %d attempts: %v", maxAttempts, lastErr)
}

func (bw *browserWorker) closeBrowser() {
	if bw.browser != nil {
		bw.browser.Close()
		bw.browser = nil
	}
}

func snapshotChromiumTmpArtifacts() map[string]struct{} {
	artifacts := make(map[string]struct{})
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		return artifacts
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".org.chromium.Chromium.") {
			artifacts[os.TempDir()+"/"+name] = struct{}{}
		}
	}
	return artifacts
}

func cleanupChromiumTmpArtifacts(before map[string]struct{}) {
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read temp dir for chromium cleanup: %v\n", err)
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, ".org.chromium.Chromium.") {
			continue
		}
		path := os.TempDir() + "/" + name
		if _, existedBefore := before[path]; existedBefore {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			fmt.Fprintf(os.Stderr, "failed to remove chromium temp artifact %s: %v\n", path, err)
		}
	}
}

func (bw *browserWorker) needsRestart() bool {
	if bw.maxRequests > 0 && bw.reqCount >= bw.maxRequests {
		return true
	}
	if bw.maxRuntime > 0 && time.Since(bw.startTime) >= bw.maxRuntime {
		return true
	}
	return false
}

func (bw *browserWorker) fetch(fullurl, header string, timeout time.Duration, contentFilterPreset string) (string, int, error) {
	if bw.needsRestart() {
		bw.closeBrowser()
		if err := bw.launch(); err != nil {
			return "", 0, fmt.Errorf("browser restart failed: %v", err)
		}
	}

	browserCtx, err := bw.browser.NewContext(playwright.BrowserNewContextOptions{
		IgnoreHttpsErrors: playwright.Bool(true),
	})
	if err != nil {
		return "", 0, fmt.Errorf("could not create browser context: %v", err)
	}

	err = browserCtx.Route("**/*", func(route playwright.Route) {
		if shouldAbortHeadlessRequest(route.Request(), contentFilterPreset) {
			if abortErr := route.Abort(); abortErr != nil {
				_ = route.Continue()
			} else if bw.stats != nil {
				bw.stats.droppedRequests.Add(1)
			}
			return
		}
		_ = route.Continue()
	})
	if err != nil {
		browserCtx.Close()
		return "", 0, fmt.Errorf("could not set route filter: %v", err)
	}

	page, err := browserCtx.NewPage()
	if err != nil {
		browserCtx.Close()
		return "", 0, fmt.Errorf("could not create page: %v", err)
	}

	if header != "" {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			if err := page.SetExtraHTTPHeaders(map[string]string{
				strings.TrimSpace(parts[0]): strings.TrimSpace(parts[1]),
			}); err != nil {
				browserCtx.Close()
				return "", 0, fmt.Errorf("could not set headers: %v", err)
			}
		}
	}

	type fetchResult struct {
		content string
		status  int
		err     error
	}
	// Buffered so the goroutine never blocks when we have already timed out.
	resultCh := make(chan fetchResult, 1)

	go func() {
		response, err := page.Goto(fullurl, playwright.PageGotoOptions{
			// Pass the same timeout to playwright as well; the Go-level timer
			// below is the authoritative hard deadline.
			Timeout:   playwright.Float(float64(timeout.Milliseconds())),
			WaitUntil: playwright.WaitUntilStateNetworkidle,
		})
		if err != nil {
			resultCh <- fetchResult{err: fmt.Errorf("navigation failed: %v", err)}
			return
		}
		status := response.Status()
		contentType, _ := response.HeaderValue("content-type")
		if shouldSkipHeadlessContent(contentType, contentFilterPreset) {
			if bw.stats != nil {
				bw.stats.skippedPages.Add(1)
			}
			resultCh <- fetchResult{status: status, content: ""}
			return
		}
		content, err := page.Content()
		if err != nil {
			resultCh <- fetchResult{status: status, err: fmt.Errorf("could not get page content: %v", err)}
			return
		}
		resultCh <- fetchResult{content: content, status: status}
	}()

	var r fetchResult
	select {
	case r = <-resultCh:
		// completed within the deadline — fall through to cleanup below

	case <-time.After(timeout):
		// Hard timeout: closing the page unblocks the goroutine (Goto/Content
		// will return with an error), which then writes to the buffered channel
		// and exits cleanly — no goroutine leak.
		page.Close()
		browserCtx.Close()
		bw.reqCount++
		return "", 0, fmt.Errorf("hard timeout (%s) exceeded for %s", timeout, fullurl)
	}

	browserCtx.Close()
	bw.reqCount++
	if r.err != nil {
		return "", r.status, r.err
	}
	return r.content, r.status, nil
}

func newHTTPClient(timeout time.Duration) *http.Client {
	t := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
		DisableKeepAlives:   true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: t,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func request(client *http.Client, fullurl, header string) (string, *http.Response) {
	ua := userAgents[rand.Intn(len(userAgents))]

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
	return string(body), resp
}

func regexGrep(content string, baseURL string, patterns []patternDef, resolvePath bool, matchInformation bool) []string {
	found := make(map[string]struct{})
	var result []string

	for _, p := range patterns {
		matches := p.Compiled.FindAllStringIndex(content, -1)

		for _, matchIdx := range matches {
			start, end := matchIdx[0], matchIdx[1]
			m := content[start:end]

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
					if strings.HasPrefix(m, "//") {
						fmt.Printf("https:%s\n", m)
					} else {
						fmt.Println(m)
					}
				}

				// Extra match information
				if matchInformation {
					var surroundingChars = 70

					snippetStart := start - surroundingChars
					if snippetStart < 0 {
						snippetStart = 0
					}
					snippetEnd := end + surroundingChars
					if snippetEnd > len(content) {
						snippetEnd = len(content)
					}
					snippet := content[snippetStart:snippetEnd]

					// Add markers if truncated
					if snippetStart > 0 {
						snippet = "..." + snippet
					}
					if snippetEnd < len(content) {
						snippet = snippet + "..."
					}

					fmt.Printf("[Match Info] [%s] [%q]\n", baseURL, snippet)
					// fmt.Printf("    Regex: %s\n", p.Regex)
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
	var matchInformation bool
	var concurrency int
	var input string
	var resolvePath bool
	var headlessMode bool
	var preflightHeadlessMode bool
	var headlessRequestsRestart int
	var headlessTimeRestart int
	var headlessPWLaunchRestart int
	var headlessPWTimeRestart int
	var substringsFilePath string
	var noTmpCleanup bool
	var headlessContentFilter string
	var showVersion bool
	var showStats bool
	var chromiumTmpBefore map[string]struct{}
	var filterStats headlessFilterStats

	flag.IntVar(&timeout, "timeout", 5, "Timeout in seconds for HTTP requests")
	flag.StringVar(&jsonFilePath, "json", "", "Path to JSON file containing additional regex patterns")
	flag.StringVar(&header, "H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36", "Custom header, e.g., -H 'User-Agent: xyz'")
	flag.BoolVar(&checkStatus, "checkstatus", false, "Check and print HTTP status of discovered links")
	flag.BoolVar(&matchInformation, "matchInfo", false, "Print more information about a match")
	flag.IntVar(&concurrency, "c", 3, "Concurrency level")
	flag.StringVar(&input, "u", "", "URL or file path to process")
	flag.BoolVar(&resolvePath, "r", false, "Resolve relative paths against base URL")
	flag.BoolVar(&headlessMode, "headless", false, "Enable headless browser mode (Playwright/Chromium) for JavaScript-rendered pages")
	flag.BoolVar(&preflightHeadlessMode, "headless-preflight", false, "Run HTTP preflight scan first; only run headless scan when preflight finds no matches (implies headless fallback)")
	flag.IntVar(&headlessRequestsRestart, "headless-requests-restart", 250, "Restart each browser process after this many requests (0 = never)")
	flag.IntVar(&headlessTimeRestart, "headless-time-restart", 900, "Restart each browser process after this many seconds of runtime (0 = never)")
	flag.IntVar(&headlessPWLaunchRestart, "headless-pw-restart-launches", 1000, "Restart the shared Playwright process after this many browser launches (0 = never)")
	flag.IntVar(&headlessPWTimeRestart, "headless-pw-restart-seconds", 10800, "Restart the shared Playwright process after this many seconds of runtime (0 = never)")
	flag.StringVar(&headlessContentFilter, "headless-content-filter", "drop-binary", "Headless response content-type filter preset: drop-binary or off")
	flag.BoolVar(&noTmpCleanup, "no-tmp-cleanup", false, "Disable cleanup of Chromium temp artifacts in /tmp after headless runs")
	flag.BoolVar(&showVersion, "version", false, "Print tool version and exit")
	flag.BoolVar(&showStats, "stats", false, "Print live status and progress information to stderr")
	flag.StringVar(&substringsFilePath, "substrings", "", "Path to newline-delimited text file of plain substrings to match (# lines and empty lines are ignored)")
	if len(os.Args) == 1 {
		fmt.Fprintln(os.Stderr, "error: no parameters provided")
		flag.Usage()
		os.Exit(1)
	}
	flag.Parse()
	if showVersion {
		fmt.Println(version)
		return
	}

	headlessEnabled := headlessMode || preflightHeadlessMode
	if _, ok := headlessContentTypeFilterPresets[headlessContentFilter]; !ok {
		fmt.Fprintf(os.Stderr, "invalid -headless-content-filter %q (allowed: drop-binary, off)\n", headlessContentFilter)
		os.Exit(1)
	}

	allPatterns := parseInternalJSON()
	if jsonFilePath != "" {
		// append
		//allPatterns = append(allPatterns, loadPatternsFromJSON(jsonFilePath)...)
		// We want to replace the whole file
		allPatterns = loadPatternsFromJSON(jsonFilePath)
	}

	// Load optional plain-substring matchers
	var substrings []string
	if substringsFilePath != "" {
		substrings = loadSubstringsFromFile(substringsFilePath)
	}

	// Start a single Playwright server process shared across all browser workers.
	var pm *playwrightManager
	if headlessEnabled {
		chromiumTmpBefore = snapshotChromiumTmpArtifacts()
		var err error
		pm, err = newPlaywrightManager(headlessPWLaunchRestart, time.Duration(headlessPWTimeRestart)*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not start playwright: %v\n", err)
			os.Exit(1)
		}
	}

	// Collect all URLs upfront so we know the total for progress reporting.
	var allURLs []string
	if fileInfo, err := os.Stat(input); err == nil && !fileInfo.IsDir() {
		f, err := os.Open(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open file: %v\n", err)
			os.Exit(1)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				allURLs = append(allURLs, line)
			}
		}
		f.Close()
	} else {
		allURLs = []string{input}
	}
	total := int64(len(allURLs))

	urlList := make(chan string, concurrency)
	go func() {
		for _, u := range allURLs {
			urlList <- u
		}
		close(urlList)
	}()

	// Progress reporter: prints to stderr every second, overwrites the line.
	var processed atomic.Int64
	startTime := time.Now()
	var statusDone chan struct{}
	var statusStopped chan struct{}
	if showStats {
		statusDone = make(chan struct{})
		statusStopped = make(chan struct{})
		restoreInteractive := startInteractiveStats(statusDone, &processed, total, startTime, headlessEnabled, headlessContentFilter, &filterStats)
		defer restoreInteractive()
		go func() {
			defer close(statusStopped)
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					n := processed.Load()
					elapsed, etaStr := progressSnapshot(n, total, startTime)
					fmt.Fprintf(os.Stderr, "\r[*] %d/%d urls | uptime: %s | eta: %s    ",
						n, total, elapsed, etaStr)
				case <-statusDone:
					return
				}
			}
		}()
	}

	wg := sync.WaitGroup{}

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Each goroutine owns one HTTP client and one browser instance (headless mode).
			timeoutDur := time.Duration(timeout) * time.Second
			httpClient := newHTTPClient(timeoutDur)

			var bw *browserWorker
			if headlessEnabled {
				var err error
				maxRuntime := time.Duration(headlessTimeRestart) * time.Second
				bw, err = newBrowserWorker(pm, &filterStats, headlessRequestsRestart, maxRuntime)
				if err != nil {
					fmt.Fprintf(os.Stderr, "could not create browser worker: %v\n", err)
					return
				}
				defer bw.closeBrowser()
			}

			for inputURL := range urlList {
				var content string
				runMatch := func(pageContent string) []string {
					if len(substrings) > 0 {
						return substringGrep(pageContent, inputURL, substrings, matchInformation)
					}
					return regexGrep(pageContent, inputURL, allPatterns, resolvePath, matchInformation)
				}

				var matches []string

				if preflightHeadlessMode {
					content, _ = request(httpClient, inputURL, header)
					matches = runMatch(content)

					if len(matches) == 0 {
						var err error
						content, _, err = bw.fetch(inputURL, header, timeoutDur, headlessContentFilter)
						if err != nil {
							fmt.Fprintf(os.Stderr, "browser fetch error: %v\n", err)
							continue
						}
						matches = runMatch(content)
					}
				} else {
					if headlessEnabled {
						var err error
						content, _, err = bw.fetch(inputURL, header, timeoutDur, headlessContentFilter)
						if err != nil {
							fmt.Fprintf(os.Stderr, "browser fetch error: %v\n", err)
							continue
						}
					} else {
						content, _ = request(httpClient, inputURL, header)
					}

					matches = runMatch(content)
				}

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

						_, resp := request(httpClient, u.String(), header)
						if resp != nil {
							fmt.Printf("[Status] %s -> %d\n", u.String(), resp.StatusCode)
						}
					}
				}

				processed.Add(1)
			}
		}()
	}
	wg.Wait()
	if headlessEnabled {
		pm.stop()
		if !noTmpCleanup {
			cleanupChromiumTmpArtifacts(chromiumTmpBefore)
		}
	}

	if showStats {
		close(statusDone)
		<-statusStopped
		elapsed, _ := progressSnapshot(processed.Load(), total, startTime)
		fmt.Fprintf(os.Stderr, "\r[*] %d/%d urls | uptime: %s | done\n",
			processed.Load(), total, elapsed)
		if headlessEnabled && headlessContentFilter != "off" {
			fmt.Fprintf(os.Stderr, "[*] headless filter stats | dropped requests: %d | skipped page bodies: %d\n",
				filterStats.droppedRequests.Load(), filterStats.skippedPages.Load())
		}
	}
}
