package analyzer

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const TypeCallGraph = "callgraph"

type CallGraphResult struct {
	Nodes       []CallNode       `json:"nodes"`
	Edges       []CallEdge       `json:"edges"`
	EntryPoints []string         `json:"entry_points,omitempty"`
	HotMethods  []HotMethod      `json:"hot_methods,omitempty"`
	Paths       []DataFlowPath   `json:"paths,omitempty"`
	Stats       CallGraphStats   `json:"stats"`
}

type CallNode struct {
	ID        string `json:"id"`
	Class     string `json:"class"`
	Method    string `json:"method"`
	File      string `json:"file"`
	CallCount int    `json:"call_count"`
}

type CallEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Line int    `json:"line"`
	Type string `json:"type"` // invoke-virtual, invoke-static, invoke-direct, invoke-interface
}

type HotMethod struct {
	ID       string `json:"id"`
	InDegree int    `json:"in_degree"`
	OutDegree int   `json:"out_degree"`
}

type DataFlowPath struct {
	Source string   `json:"source"`
	Sink   string   `json:"sink"`
	Path   []string `json:"path"`
	Risk   string   `json:"risk"`
}

type CallGraphStats struct {
	TotalNodes  int `json:"total_nodes"`
	TotalEdges  int `json:"total_edges"`
	MaxInDegree int `json:"max_in_degree"`
	MaxOutDegree int `json:"max_out_degree"`
}

var (
	reSmaliMethod = regexp.MustCompile(`^\.method\s+(.*?)\s+(\S+)\(`)
	reSmaliEnd    = regexp.MustCompile(`^\.end method`)
	reSmaliInvoke = regexp.MustCompile(`invoke-(virtual|static|direct|interface|super)\s+\{[^}]*\},\s+(\S+)`)
	reSmaliClass  = regexp.MustCompile(`^\.class\s+.*\s+(L[^;]+;)`)
)

var taintSources = map[string]bool{
	"Landroid/content/SharedPreferences;->getString":       true,
	"Landroid/content/Intent;->getStringExtra":             true,
	"Landroid/content/Intent;->getData":                    true,
	"Landroid/database/Cursor;->getString":                 true,
	"Landroid/location/Location;->getLatitude":             true,
	"Landroid/location/Location;->getLongitude":            true,
	"Landroid/telephony/TelephonyManager;->getDeviceId":   true,
	"Landroid/telephony/TelephonyManager;->getLine1Number": true,
	"Landroid/accounts/AccountManager;->getAccounts":      true,
	"Ljava/io/BufferedReader;->readLine":                   true,
	"Landroid/content/ContentResolver;->query":            true,
	"Landroid/webkit/WebView;->getUrl":                    true,
	"Landroid/os/Bundle;->getString":                      true,
}

var taintSinks = map[string]bool{
	"Landroid/util/Log;->d":                               true,
	"Landroid/util/Log;->i":                               true,
	"Landroid/util/Log;->e":                               true,
	"Landroid/util/Log;->v":                               true,
	"Ljava/net/HttpURLConnection;->getOutputStream":       true,
	"Lorg/apache/http/client/HttpClient;->execute":        true,
	"Landroid/content/SharedPreferences$Editor;->putString": true,
	"Landroid/database/sqlite/SQLiteDatabase;->execSQL":   true,
	"Landroid/database/sqlite/SQLiteDatabase;->rawQuery":  true,
	"Ljava/io/FileOutputStream;->write":                   true,
	"Landroid/content/Intent;->putExtra":                  true,
	"Landroid/webkit/WebView;->loadUrl":                   true,
	"Ljava/net/URL;->openConnection":                      true,
	"Lokhttp3/OkHttpClient;->newCall":                     true,
}

func BuildCallGraph(decompiledPath string, targetPackage string) (*CallGraphResult, error) {
	result := &CallGraphResult{}
	if decompiledPath == "" {
		return result, nil
	}

	nodes := map[string]*CallNode{}
	var edges []CallEdge
	inDegree := map[string]int{}
	outDegree := map[string]int{}

	smaliDirs := findSmaliDirs(decompiledPath)

	for _, smaliDir := range smaliDirs {
		_ = filepath.WalkDir(smaliDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".smali") {
				return nil
			}

			if targetPackage != "" {
				rel, _ := filepath.Rel(decompiledPath, path)
				pkgPath := strings.ReplaceAll(targetPackage, ".", "/")
				if !strings.Contains(rel, pkgPath) {
					return nil
				}
			}

			classEdges := parseSmaliFile(path, decompiledPath, nodes)
			edges = append(edges, classEdges...)
			return nil
		})
	}

	for _, e := range edges {
		inDegree[e.To]++
		outDegree[e.From]++
	}

	for id, node := range nodes {
		node.CallCount = inDegree[id]
		result.Nodes = append(result.Nodes, *node)
	}

	sort.Slice(result.Nodes, func(i, j int) bool {
		return result.Nodes[i].CallCount > result.Nodes[j].CallCount
	})
	if len(result.Nodes) > 500 {
		result.Nodes = result.Nodes[:500]
	}

	if len(edges) > 2000 {
		edges = edges[:2000]
	}
	result.Edges = edges

	for id := range nodes {
		in := inDegree[id]
		out := outDegree[id]
		if in >= 5 || out >= 10 {
			result.HotMethods = append(result.HotMethods, HotMethod{
				ID:        id,
				InDegree:  in,
				OutDegree: out,
			})
		}
	}
	sort.Slice(result.HotMethods, func(i, j int) bool {
		return result.HotMethods[i].InDegree+result.HotMethods[i].OutDegree >
			result.HotMethods[j].InDegree+result.HotMethods[j].OutDegree
	})
	if len(result.HotMethods) > 50 {
		result.HotMethods = result.HotMethods[:50]
	}

	result.Paths = findTaintPaths(edges, nodes)

	maxIn, maxOut := 0, 0
	for _, v := range inDegree {
		if v > maxIn {
			maxIn = v
		}
	}
	for _, v := range outDegree {
		if v > maxOut {
			maxOut = v
		}
	}
	result.Stats = CallGraphStats{
		TotalNodes:   len(nodes),
		TotalEdges:   len(edges),
		MaxInDegree:  maxIn,
		MaxOutDegree: maxOut,
	}

	for _, node := range result.Nodes {
		if inDegree[node.ID] == 0 && outDegree[node.ID] > 0 {
			if strings.Contains(node.Method, "onCreate") ||
				strings.Contains(node.Method, "onReceive") ||
				strings.Contains(node.Method, "onStartCommand") ||
				strings.Contains(node.Method, "main") {
				result.EntryPoints = append(result.EntryPoints, node.ID)
			}
		}
	}
	if len(result.EntryPoints) > 30 {
		result.EntryPoints = result.EntryPoints[:30]
	}

	return result, nil
}

func findSmaliDirs(base string) []string {
	var dirs []string
	entries, _ := os.ReadDir(base)
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "smali") {
			dirs = append(dirs, filepath.Join(base, e.Name()))
		}
	}
	if len(dirs) == 0 {
		dirs = append(dirs, filepath.Join(base, "smali"))
	}
	return dirs
}

func parseSmaliFile(path, baseDir string, nodes map[string]*CallNode) []CallEdge {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	rel, _ := filepath.Rel(baseDir, path)
	var edges []CallEdge
	var currentClass string
	var currentMethod string
	var currentMethodID string

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		if m := reSmaliClass.FindStringSubmatch(line); len(m) > 1 {
			currentClass = m[1]
			continue
		}

		if m := reSmaliMethod.FindStringSubmatch(line); len(m) > 2 {
			currentMethod = m[2]
			currentMethodID = currentClass + "->" + currentMethod
			if _, ok := nodes[currentMethodID]; !ok {
				nodes[currentMethodID] = &CallNode{
					ID:     currentMethodID,
					Class:  smaliToJava(currentClass),
					Method: currentMethod,
					File:   rel,
				}
			}
			continue
		}

		if reSmaliEnd.MatchString(line) {
			currentMethod = ""
			currentMethodID = ""
			continue
		}

		if currentMethodID == "" {
			continue
		}

		if m := reSmaliInvoke.FindStringSubmatch(line); len(m) > 2 {
			invokeType := m[1]
			target := m[2]

			if _, ok := nodes[target]; !ok {
				parts := strings.SplitN(target, "->", 2)
				cls := ""
				meth := target
				if len(parts) == 2 {
					cls = smaliToJava(parts[0])
					meth = parts[1]
				}
				nodes[target] = &CallNode{
					ID:     target,
					Class:  cls,
					Method: meth,
				}
			}

			edges = append(edges, CallEdge{
				From: currentMethodID,
				To:   target,
				Line: lineNo,
				Type: "invoke-" + invokeType,
			})
		}
	}

	return edges
}

func smaliToJava(smaliClass string) string {
	s := strings.TrimPrefix(smaliClass, "L")
	s = strings.TrimSuffix(s, ";")
	return strings.ReplaceAll(s, "/", ".")
}

func findTaintPaths(edges []CallEdge, nodes map[string]*CallNode) []DataFlowPath {
	adj := map[string][]string{}
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e.To)
	}

	var paths []DataFlowPath
	sourceNodes := []string{}
	sinkNodes := []string{}

	for id := range nodes {
		for src := range taintSources {
			if strings.Contains(id, src) {
				sourceNodes = append(sourceNodes, id)
				break
			}
		}
		for sink := range taintSinks {
			if strings.Contains(id, sink) {
				sinkNodes = append(sinkNodes, id)
				break
			}
		}
	}

	for _, src := range sourceNodes {
		for _, sink := range sinkNodes {
			if path := bfsPath(adj, src, sink, 6); path != nil {
				risk := "medium"
				if isSensitiveSource(src) && isDangerousSink(sink) {
					risk = "high"
				}
				paths = append(paths, DataFlowPath{
					Source: src,
					Sink:   sink,
					Path:   path,
					Risk:   risk,
				})
				if len(paths) >= 20 {
					return paths
				}
			}
		}
	}

	return paths
}

func bfsPath(adj map[string][]string, start, end string, maxDepth int) []string {
	if start == end {
		return nil
	}
	type state struct {
		node string
		path []string
	}
	visited := map[string]bool{start: true}
	queue := []state{{node: start, path: []string{start}}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		if len(cur.path) > maxDepth {
			continue
		}

		for _, next := range adj[cur.node] {
			if next == end {
				return append(cur.path, end)
			}
			if !visited[next] {
				visited[next] = true
				newPath := make([]string, len(cur.path)+1)
				copy(newPath, cur.path)
				newPath[len(cur.path)] = next
				queue = append(queue, state{node: next, path: newPath})
			}
		}
	}
	return nil
}

func isSensitiveSource(id string) bool {
	sensitive := []string{"getDeviceId", "getLine1Number", "getAccounts", "getLatitude", "getLongitude", "query"}
	for _, s := range sensitive {
		if strings.Contains(id, s) {
			return true
		}
	}
	return false
}

func isDangerousSink(id string) bool {
	dangerous := []string{"execSQL", "rawQuery", "loadUrl", "openConnection", "execute", "newCall"}
	for _, s := range dangerous {
		if strings.Contains(id, s) {
			return true
		}
	}
	return false
}
