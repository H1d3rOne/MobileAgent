package analyzer

import (
	"bufio"
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

const TypeNetwork = "network"

type NetworkResult struct {
	Requests    []CapturedRequest `json:"requests"`
	Summary     NetworkSummary    `json:"summary"`
	APIEndpoints []APIEndpoint   `json:"api_endpoints,omitempty"`
	Domains     []DomainStats    `json:"domains,omitempty"`
}

type CapturedRequest struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Host        string            `json:"host"`
	Path        string            `json:"path"`
	StatusCode  int               `json:"status_code,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	HasBody     bool              `json:"has_body"`
	Category    string            `json:"category"`
}

type NetworkSummary struct {
	TotalRequests int            `json:"total_requests"`
	ByMethod      map[string]int `json:"by_method"`
	ByCategory    map[string]int `json:"by_category"`
	UniqueHosts   int            `json:"unique_hosts"`
	HasHTTPS      bool           `json:"has_https"`
	HasHTTP       bool           `json:"has_http"`
}

type APIEndpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Host   string `json:"host"`
	Count  int    `json:"count"`
}

type DomainStats struct {
	Domain   string `json:"domain"`
	Count    int    `json:"count"`
	Category string `json:"category"`
}

var (
	reMitmFlow    = regexp.MustCompile(`(?m)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(https?://\S+)`)
	reMitmStatus  = regexp.MustCompile(`(?m)<<\s+(\d{3})`)
	reMitmHeader  = regexp.MustCompile(`(?m)^\s+([\w-]+):\s+(.+)$`)
	reHARMethod   = regexp.MustCompile(`"method"\s*:\s*"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"`)
	reHARURL      = regexp.MustCompile(`"url"\s*:\s*"([^"]+)"`)
	reHARStatus   = regexp.MustCompile(`"status"\s*:\s*(\d+)`)
)

func ParseNetworkCapture(filePath string) (*NetworkResult, error) {
	result := &NetworkResult{
		Summary: NetworkSummary{
			ByMethod:   map[string]int{},
			ByCategory: map[string]int{},
		},
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return result, err
	}
	content := string(data)

	if isHARFormat(content) {
		parseHAR(content, result)
	} else if isMitmproxyFormat(content) {
		parseMitmproxy(content, result)
	} else {
		parseGenericCapture(content, result)
	}

	computeNetworkSummary(result)
	return result, nil
}

func ParseNetworkLines(lines []string) (*NetworkResult, error) {
	result := &NetworkResult{
		Summary: NetworkSummary{
			ByMethod:   map[string]int{},
			ByCategory: map[string]int{},
		},
	}

	content := strings.Join(lines, "\n")
	if isMitmproxyFormat(content) {
		parseMitmproxy(content, result)
	} else {
		parseGenericCapture(content, result)
	}

	computeNetworkSummary(result)
	return result, nil
}

func ParseNetworkFromFile(path string) (*NetworkResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return ParseNetworkLines(lines)
}

func isHARFormat(content string) bool {
	return strings.Contains(content, `"log"`) && strings.Contains(content, `"entries"`)
}

func isMitmproxyFormat(content string) bool {
	return reMitmFlow.MatchString(content)
}

func parseHAR(content string, result *NetworkResult) {
	var har struct {
		Log struct {
			Entries []struct {
				Request struct {
					Method  string `json:"method"`
					URL     string `json:"url"`
					Headers []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"headers"`
				} `json:"request"`
				Response struct {
					Status  int `json:"status"`
					Content struct {
						MimeType string `json:"mimeType"`
					} `json:"content"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}

	if err := json.Unmarshal([]byte(content), &har); err != nil {
		matches := reHARURL.FindAllStringSubmatch(content, -1)
		methods := reHARMethod.FindAllStringSubmatch(content, -1)
		for i, m := range matches {
			method := "GET"
			if i < len(methods) {
				method = methods[i][1]
			}
			req := buildRequest(method, m[1])
			result.Requests = append(result.Requests, req)
		}
		return
	}

	for _, entry := range har.Log.Entries {
		req := buildRequest(entry.Request.Method, entry.Request.URL)
		req.StatusCode = entry.Response.Status
		req.ContentType = entry.Response.Content.MimeType
		headers := map[string]string{}
		for _, h := range entry.Request.Headers {
			low := strings.ToLower(h.Name)
			if low == "authorization" || low == "cookie" || low == "x-api-key" || low == "content-type" {
				headers[h.Name] = maskHeaderValue(h.Name, h.Value)
			}
		}
		if len(headers) > 0 {
			req.Headers = headers
		}
		result.Requests = append(result.Requests, req)
	}
}

func parseMitmproxy(content string, result *NetworkResult) {
	matches := reMitmFlow.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		req := buildRequest(m[1], m[2])
		result.Requests = append(result.Requests, req)
	}
}

func parseGenericCapture(content string, result *NetworkResult) {
	reGeneric := regexp.MustCompile(`(?m)(GET|POST|PUT|DELETE|PATCH)\s+(\S+)`)
	matches := reGeneric.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		rawURL := m[2]
		if !strings.HasPrefix(rawURL, "http") {
			rawURL = "https://unknown" + rawURL
		}
		req := buildRequest(m[1], rawURL)
		result.Requests = append(result.Requests, req)
	}
}

func buildRequest(method, rawURL string) CapturedRequest {
	req := CapturedRequest{
		Method: method,
		URL:    rawURL,
	}
	if parsed, err := url.Parse(rawURL); err == nil {
		req.Host = parsed.Host
		req.Path = parsed.Path
		if strings.HasPrefix(rawURL, "https") {
			req.HasBody = method == "POST" || method == "PUT" || method == "PATCH"
		}
	}
	req.Category = classifyRequestDomain(req.Host)
	return req
}

func classifyRequestDomain(host string) string {
	low := strings.ToLower(host)
	for _, d := range analyticsDomains {
		if strings.Contains(low, d) {
			return "analytics"
		}
	}
	for _, d := range adDomains {
		if strings.Contains(low, d) {
			return "ad"
		}
	}
	for _, d := range cloudDomains {
		if strings.Contains(low, d) {
			return "cloud"
		}
	}
	for _, d := range cdnDomains {
		if strings.Contains(low, d) {
			return "cdn"
		}
	}
	for _, d := range socialDomains {
		if strings.Contains(low, d) {
			return "social"
		}
	}
	for _, d := range paymentDomains {
		if strings.Contains(low, d) {
			return "payment"
		}
	}
	return "app"
}

func maskHeaderValue(name, value string) string {
	low := strings.ToLower(name)
	if low == "authorization" || low == "x-api-key" || low == "cookie" {
		if len(value) > 12 {
			return value[:8] + "***"
		}
		return "***"
	}
	return value
}

func computeNetworkSummary(result *NetworkResult) {
	hosts := map[string]int{}
	endpoints := map[string]int{}

	for _, req := range result.Requests {
		result.Summary.ByMethod[req.Method]++
		result.Summary.ByCategory[req.Category]++
		hosts[req.Host]++
		if strings.HasPrefix(req.URL, "https") {
			result.Summary.HasHTTPS = true
		} else {
			result.Summary.HasHTTP = true
		}
		key := req.Method + " " + req.Host + req.Path
		endpoints[key]++
	}

	result.Summary.TotalRequests = len(result.Requests)
	result.Summary.UniqueHosts = len(hosts)

	for host, count := range hosts {
		result.Domains = append(result.Domains, DomainStats{
			Domain:   host,
			Count:    count,
			Category: classifyRequestDomain(host),
		})
	}
	sort.Slice(result.Domains, func(i, j int) bool {
		return result.Domains[i].Count > result.Domains[j].Count
	})

	for key, count := range endpoints {
		parts := strings.SplitN(key, " ", 2)
		method := parts[0]
		hostPath := parts[1]
		idx := strings.Index(hostPath, "/")
		host := hostPath
		path := "/"
		if idx > 0 {
			host = hostPath[:idx]
			path = hostPath[idx:]
		}
		result.APIEndpoints = append(result.APIEndpoints, APIEndpoint{
			Method: method,
			Host:   host,
			Path:   path,
			Count:  count,
		})
	}
	sort.Slice(result.APIEndpoints, func(i, j int) bool {
		return result.APIEndpoints[i].Count > result.APIEndpoints[j].Count
	})

	if len(result.APIEndpoints) > 100 {
		result.APIEndpoints = result.APIEndpoints[:100]
	}
	if len(result.Domains) > 50 {
		result.Domains = result.Domains[:50]
	}
	if len(result.Requests) > 500 {
		result.Requests = result.Requests[:500]
	}
}
