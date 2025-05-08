# Regexr

`go install github.com/m-1tZ/regexr@latest`

Yet another regex pattern detection tool that comes along with built-in headless support with playwright-go.

```
Usage:
  -H string
        Custom header, e.g., -H 'User-Agent: xyz' (default "User-Agent: Chrome")
  -c int
        Concurrency level (default 3)
  -checkstatus
        Check and print HTTP status of discovered links
  -json string
        Path to JSON file containing additional regex patterns
  -noheadless
        Disables headless mode
  -r    Resolve relative paths against base URL
  -timeout int
        Timeout in seconds for HTTP requests (default 7)
  -u string
        URL or file path to process
```

Externally specified regex json file should look like:
```json
{
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
}
```