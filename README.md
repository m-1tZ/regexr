# Regexr

`go install github.com/m-1tZ/regexr@latest`

Yet another regex pattern detection tool that comes along with built-in headless support with playwright-go.

```
Usage of regexr:
  -H string
    	Custom header, e.g., -H 'User-Agent: xyz' (default "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36")
  -c int
    	Concurrency level (default 3)
  -checkstatus
    	Check and print HTTP status of discovered links
  -headless
    	Enable headless browser mode (Playwright/Chromium) for JavaScript-rendered pages
  -headless-content-filter string
    	Headless response content-type filter preset: drop-binary or off (default "drop-binary")
  -headless-preflight
    	Run HTTP preflight scan first; only run headless scan when preflight finds no matches (implies headless fallback)
  -headless-pw-restart-launches int
    	Restart the shared Playwright process after this many browser launches (0 = never) (default 1000)
  -headless-pw-restart-seconds int
    	Restart the shared Playwright process after this many seconds of runtime (0 = never) (default 10800)
  -headless-requests-restart int
    	Restart each browser process after this many requests (0 = never) (default 250)
  -headless-time-restart int
    	Restart each browser process after this many seconds of runtime (0 = never) (default 900)
  -json string
    	Path to JSON file containing additional regex patterns
  -matchInfo
    	Print more information about a match
  -no-tmp-cleanup
    	Disable cleanup of Chromium temp artifacts in /tmp after headless runs
  -r	Resolve relative paths against base URL
  -stats
    	Print live status and progress information to stderr
  -substrings string
    	Path to newline-delimited text file of plain substrings to match (# lines and empty lines are ignored)
  -timeout int
    	Timeout in seconds for HTTP requests (default 5)
  -u string
    	URL or file path to process
  -version
    	Print tool version and exit

```

Externally specified regex json file should look like:
```json
{
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
}
```


# TODO
https://www.reddit.com/r/golang/comments/1rlala0/lessons_from_managing_hundreds_of_headless_chrome/
