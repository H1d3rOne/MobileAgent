package analyzer

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const TypeDiff = "diff"

type DiffResult struct {
	Summary        DiffSummary       `json:"summary"`
	Permissions    DiffList          `json:"permissions"`
	Components     ComponentDiff     `json:"components"`
	Files          FileDiff          `json:"files"`
	NativeLibs     DiffList          `json:"native_libs"`
	SDKChanges     DiffList          `json:"sdk_changes,omitempty"`
	ManifestDelta  map[string][2]any `json:"manifest_delta,omitempty"`
}

type DiffSummary struct {
	TotalAdded   int `json:"total_added"`
	TotalRemoved int `json:"total_removed"`
	TotalChanged int `json:"total_changed"`
	RiskDelta    int `json:"risk_delta"`
}

type DiffList struct {
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

type ComponentDiff struct {
	Activities DiffList `json:"activities"`
	Services   DiffList `json:"services"`
	Receivers  DiffList `json:"receivers"`
	Providers  DiffList `json:"providers"`
}

type FileDiff struct {
	Added    []string      `json:"added,omitempty"`
	Removed  []string      `json:"removed,omitempty"`
	Modified []FileChanged `json:"modified,omitempty"`
}

type FileChanged struct {
	Path    string `json:"path"`
	OldHash string `json:"old_hash"`
	NewHash string `json:"new_hash"`
	SizeDif int64  `json:"size_diff"`
}

func DiffAPKs(oldDecompiledPath, newDecompiledPath string) (*DiffResult, error) {
	result := &DiffResult{
		ManifestDelta: map[string][2]any{},
	}

	if oldDecompiledPath == "" || newDecompiledPath == "" {
		return result, fmt.Errorf("both APKs must be decompiled for diff")
	}

	oldManifest, _ := ParseManifest(filepath.Join(oldDecompiledPath, "AndroidManifest.xml"))
	newManifest, _ := ParseManifest(filepath.Join(newDecompiledPath, "AndroidManifest.xml"))

	if oldManifest != nil && newManifest != nil {
		result.Permissions = diffStringSlices(oldManifest.Permissions, newManifest.Permissions)
		result.Components.Activities = diffComponents(oldManifest.Activities, newManifest.Activities)
		result.Components.Services = diffComponents(oldManifest.Services, newManifest.Services)
		result.Components.Receivers = diffComponents(oldManifest.Receivers, newManifest.Receivers)
		result.Components.Providers = diffComponents(oldManifest.Providers, newManifest.Providers)

		if oldManifest.MinSDK != newManifest.MinSDK {
			result.ManifestDelta["min_sdk"] = [2]any{oldManifest.MinSDK, newManifest.MinSDK}
		}
		if oldManifest.TargetSDK != newManifest.TargetSDK {
			result.ManifestDelta["target_sdk"] = [2]any{oldManifest.TargetSDK, newManifest.TargetSDK}
		}
		if oldManifest.Debuggable != newManifest.Debuggable {
			result.ManifestDelta["debuggable"] = [2]any{oldManifest.Debuggable, newManifest.Debuggable}
		}
		if oldManifest.AllowBackup != newManifest.AllowBackup {
			result.ManifestDelta["allow_backup"] = [2]any{oldManifest.AllowBackup, newManifest.AllowBackup}
		}
		if oldManifest.UsesCleartextTraffic != newManifest.UsesCleartextTraffic {
			result.ManifestDelta["cleartext_traffic"] = [2]any{oldManifest.UsesCleartextTraffic, newManifest.UsesCleartextTraffic}
		}
	}

	oldLibs := collectNativeLibs(oldDecompiledPath)
	newLibs := collectNativeLibs(newDecompiledPath)
	result.NativeLibs = diffStringSlices(oldLibs, newLibs)

	oldSDKs, _ := DetectSDKs(oldDecompiledPath)
	newSDKs, _ := DetectSDKs(newDecompiledPath)
	if oldSDKs != nil && newSDKs != nil {
		oldNames := sdkNames(oldSDKs)
		newNames := sdkNames(newSDKs)
		result.SDKChanges = diffStringSlices(oldNames, newNames)
	}

	result.Files = diffFiles(oldDecompiledPath, newDecompiledPath)

	result.Summary.TotalAdded = len(result.Permissions.Added) + len(result.Files.Added) +
		len(result.Components.Activities.Added) + len(result.Components.Services.Added) +
		len(result.Components.Receivers.Added) + len(result.Components.Providers.Added) +
		len(result.NativeLibs.Added)
	result.Summary.TotalRemoved = len(result.Permissions.Removed) + len(result.Files.Removed) +
		len(result.Components.Activities.Removed) + len(result.Components.Services.Removed) +
		len(result.Components.Receivers.Removed) + len(result.Components.Providers.Removed) +
		len(result.NativeLibs.Removed)
	result.Summary.TotalChanged = len(result.Files.Modified)

	riskDelta := 0
	dangerousPerms := map[string]bool{
		"android.permission.READ_SMS": true, "android.permission.SEND_SMS": true,
		"android.permission.READ_CONTACTS": true, "android.permission.CAMERA": true,
		"android.permission.RECORD_AUDIO": true, "android.permission.ACCESS_FINE_LOCATION": true,
		"android.permission.READ_PHONE_STATE": true, "android.permission.WRITE_EXTERNAL_STORAGE": true,
		"android.permission.INSTALL_PACKAGES": true, "android.permission.REQUEST_INSTALL_PACKAGES": true,
	}
	for _, p := range result.Permissions.Added {
		if dangerousPerms[p] {
			riskDelta += 10
		}
	}
	for _, p := range result.Permissions.Removed {
		if dangerousPerms[p] {
			riskDelta -= 5
		}
	}
	result.Summary.RiskDelta = riskDelta

	return result, nil
}

func diffStringSlices(old, new []string) DiffList {
	oldSet := toSet(old)
	newSet := toSet(new)
	dl := DiffList{}
	for _, s := range new {
		if !oldSet[s] {
			dl.Added = append(dl.Added, s)
		}
	}
	for _, s := range old {
		if !newSet[s] {
			dl.Removed = append(dl.Removed, s)
		}
	}
	return dl
}

func diffComponents(old, new []Component) DiffList {
	oldNames := make([]string, len(old))
	for i, c := range old {
		oldNames[i] = c.Name
	}
	newNames := make([]string, len(new))
	for i, c := range new {
		newNames[i] = c.Name
	}
	return diffStringSlices(oldNames, newNames)
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func collectNativeLibs(dir string) []string {
	var libs []string
	libDir := filepath.Join(dir, "lib")
	_ = filepath.WalkDir(libDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(d.Name(), ".so") {
			rel, _ := filepath.Rel(dir, path)
			libs = append(libs, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(libs)
	return libs
}

func sdkNames(result *SDKResult) []string {
	names := make([]string, len(result.SDKs))
	for i, s := range result.SDKs {
		names[i] = s.Name
	}
	sort.Strings(names)
	return names
}

func diffFiles(oldDir, newDir string) FileDiff {
	oldFiles := indexFiles(oldDir)
	newFiles := indexFiles(newDir)

	fd := FileDiff{}
	for path := range newFiles {
		if _, ok := oldFiles[path]; !ok {
			fd.Added = append(fd.Added, path)
		}
	}
	for path := range oldFiles {
		if _, ok := newFiles[path]; !ok {
			fd.Removed = append(fd.Removed, path)
		}
	}
	for path, newInfo := range newFiles {
		if oldInfo, ok := oldFiles[path]; ok {
			if oldInfo.hash != newInfo.hash {
				fd.Modified = append(fd.Modified, FileChanged{
					Path:    path,
					OldHash: oldInfo.hash[:12],
					NewHash: newInfo.hash[:12],
					SizeDif: newInfo.size - oldInfo.size,
				})
			}
		}
	}

	sort.Strings(fd.Added)
	sort.Strings(fd.Removed)
	sort.Slice(fd.Modified, func(i, j int) bool { return fd.Modified[i].Path < fd.Modified[j].Path })

	if len(fd.Added) > 200 {
		fd.Added = fd.Added[:200]
	}
	if len(fd.Removed) > 200 {
		fd.Removed = fd.Removed[:200]
	}
	if len(fd.Modified) > 200 {
		fd.Modified = fd.Modified[:200]
	}
	return fd
}

type fileInfo struct {
	hash string
	size int64
}

func indexFiles(dir string) map[string]fileInfo {
	files := map[string]fileInfo{}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		relSlash := filepath.ToSlash(rel)
		info, err := d.Info()
		if err != nil {
			return nil
		}
		h := hashFile(path)
		files[relSlash] = fileInfo{hash: h, size: info.Size()}
		return nil
	})
	return files
}

func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	r := bufio.NewReader(f)
	_, _ = io.Copy(h, r)
	return hex.EncodeToString(h.Sum(nil))
}
