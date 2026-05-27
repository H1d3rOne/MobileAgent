package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/gin-gonic/gin"
	"github.com/mobileagent/backend-go/internal/agent"
	"github.com/mobileagent/backend-go/internal/analyzer"
	"github.com/mobileagent/backend-go/internal/config"
	"github.com/mobileagent/backend-go/internal/frida"
	"github.com/mobileagent/backend-go/internal/model"
	"github.com/mobileagent/backend-go/internal/runner"
	"github.com/mobileagent/backend-go/internal/store"
	"github.com/mobileagent/backend-go/internal/util"
)

type APKHandler struct {
	store  *store.APKStore
	runner *runner.APKRunner
	cfg    *config.Config
}

func NewAPKHandler(s *store.APKStore, r *runner.APKRunner, cfg *config.Config) *APKHandler {
	return &APKHandler{store: s, runner: r, cfg: cfg}
}

func (h *APKHandler) List(c *gin.Context) {
	apks, err := h.store.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: apks})
}

func (h *APKHandler) Get(c *gin.Context) {
	id := c.Param("id")
	apk, err := h.store.Get(id)
	if err != nil {
		c.JSON(http.StatusNotFound, model.APIResponse{Success: false, Error: "APK not found"})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: apk})
}

func (h *APKHandler) Upload(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "No file uploaded"})
		return
	}

	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	defer src.Close()

	data := make([]byte, file.Size)
	if _, err := src.Read(data); err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	savedPath, err := h.runner.SaveUploadedFile(file.Filename, data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	apk := &model.APK{
		ID:       util.NewID(),
		Filename: file.Filename,
		FilePath: savedPath,
		FileSize: file.Size,
		Status:   "uploaded",
	}

	if err := h.store.Create(apk); err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	c.JSON(http.StatusCreated, model.APIResponse{Success: true, Data: apk})
}

func (h *APKHandler) Analyze(c *gin.Context) {
	id := c.Param("id")
	apk, err := h.store.Get(id)
	if err != nil {
		c.JSON(http.StatusNotFound, model.APIResponse{Success: false, Error: "APK not found"})
		return
	}

	analysis, err := h.runner.Analyze(apk)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	// Update APK info from analysis
	h.store.Update(apk)

	if err := h.store.CreateAnalysis(analysis); err != nil {
		zap.L().Warn("Failed to save analysis", zap.Error(err))
	}

	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: analysis})
}

func (h *APKHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.store.Delete(id); err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true})
}

func (h *APKHandler) Install(c *gin.Context) {
	id := c.Param("id")
	apk, err := h.store.Get(id)
	if err != nil {
		c.JSON(http.StatusNotFound, model.APIResponse{Success: false, Error: "APK not found"})
		return
	}

	serial := c.Query("device")
	if serial == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "device serial required"})
		return
	}

	result, err := h.runner.InstallToDevice(serial, apk.FilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	apk.Status = "installed"
	h.store.Update(apk)

	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: result})
}

func (h *APKHandler) ListAnalysis(c *gin.Context) {
	id := c.Param("id")
	results, err := h.store.ListAnalysis(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: results})
}

func (h *APKHandler) Decompile(c *gin.Context) {
	id := c.Param("id")
	apk, err := h.store.Get(id)
	if err != nil {
		c.JSON(http.StatusNotFound, model.APIResponse{Success: false, Error: "APK not found"})
		return
	}

	tool := c.DefaultQuery("tool", "apktool")
	outputDir := "/tmp/decompile_" + apk.ID

	var result string
	if tool == "jadx" {
		result, err = h.runner.DecompileWithJADX(apk.FilePath, outputDir)
	} else {
		result, err = h.runner.Decompile(apk.FilePath, outputDir)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: map[string]string{"output_dir": result}})
}

// UploadAndAnalyze uploads an APK file and immediately analyzes it
func (h *APKHandler) UploadAndAnalyze(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "No file uploaded"})
		return
	}

	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	defer src.Close()

	data := make([]byte, file.Size)
	if _, err := src.Read(data); err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	savedPath, err := h.runner.SaveUploadedFile(file.Filename, data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	apk := &model.APK{
		ID:       util.NewID(),
		Filename: file.Filename,
		FilePath: savedPath,
		FileSize: file.Size,
		Status:   "uploaded",
	}

	if err := h.store.Create(apk); err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	// Auto-analyze after upload
	analysis, err := h.runner.Analyze(apk)
	if err != nil {
		zap.L().Warn("Auto-analysis failed", zap.Error(err))
		c.JSON(http.StatusCreated, model.APIResponse{Success: true, Data: apk})
		return
	}

	h.store.Update(apk)
	if err := h.store.CreateAnalysis(analysis); err != nil {
		zap.L().Warn("Failed to save analysis", zap.Error(err))
	}

	c.JSON(http.StatusCreated, model.APIResponse{Success: true, Data: map[string]interface{}{
		"apk":      apk,
		"analysis": analysis,
	}})
}

// DecompileByPath decompiles an APK by its file path or id, persists the
// decompiled output dir on the APK record, and returns the output path.
func (h *APKHandler) DecompileByPath(c *gin.Context) {
	var req struct {
		ID   string `json:"id"`
		Path string `json:"path"`
		Tool string `json:"tool"`
	}
	_ = c.ShouldBindJSON(&req)
	if req.ID == "" {
		req.ID = c.Query("id")
	}
	if req.Path == "" {
		req.Path = c.Query("path")
	}
	if req.Tool == "" {
		req.Tool = c.DefaultQuery("tool", "apktool")
	}

	// Resolve APK record by id or path so we can persist decompile state.
	var apk *model.APK
	if req.ID != "" {
		apk, _ = h.store.Get(req.ID)
	}
	if apk == nil && req.Path != "" {
		apk, _ = h.store.FindByPath(req.Path)
	}
	if req.Path == "" && apk != nil {
		req.Path = apk.FilePath
	}
	if req.Path == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "apk path or id required"})
		return
	}

	// Use a stable per-APK output dir under the workspace so it persists.
	base := h.cfg.Storage.WorkspaceDir
	if base == "" {
		base = "/tmp"
	}
	dirID := req.ID
	if dirID == "" && apk != nil {
		dirID = apk.ID
	}
	if dirID == "" {
		dirID = util.NewID()
	}
	outputDir := filepath.Join(base, "decompiled", dirID+"_"+req.Tool)
	_ = os.RemoveAll(outputDir)

	var result string
	var err error
	if req.Tool == "jadx" {
		result, err = h.runner.DecompileWithJADX(req.Path, outputDir)
	} else {
		result, err = h.runner.Decompile(req.Path, outputDir)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	if apk != nil {
		now := time.Now()
		apk.DecompiledTool = req.Tool
		apk.DecompiledPath = result
		apk.DecompiledAt = &now
		apk.Status = "decompiled"
		_ = h.store.Update(apk)
	}

	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: map[string]any{
		"output_dir":    result,
		"tool":          req.Tool,
		"decompiled_at": time.Now(),
		"apk":           apk,
	}})
}

// BrowseDir lists entries inside a decompiled output directory, scoped to the
// workspace to prevent path traversal.
func (h *APKHandler) BrowseDir(c *gin.Context) {
	dir := c.Query("dir")
	if dir == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "dir required"})
		return
	}
	abs, err := h.secureWorkspacePath(dir)
	if err != nil {
		respondPathScopeError(c, err)
		return
	}

	entries, err := os.ReadDir(abs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		out = append(out, map[string]any{
			"name":     e.Name(),
			"path":     filepath.Join(abs, e.Name()),
			"is_dir":   e.IsDir(),
			"size":     info.Size(),
			"modified": info.ModTime(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		di := out[i]["is_dir"].(bool)
		dj := out[j]["is_dir"].(bool)
		if di != dj {
			return di
		}
		return out[i]["name"].(string) < out[j]["name"].(string)
	})
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: map[string]any{
		"dir":     abs,
		"entries": out,
	}})
}

// BrowseFile returns file content from a decompiled APK directory.
func (h *APKHandler) BrowseFile(c *gin.Context) {
	dir := c.Query("dir")
	filePath := c.Query("file")
	if dir == "" || filePath == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "dir and file params required"})
		return
	}
	if filepath.IsAbs(filePath) {
		c.JSON(http.StatusForbidden, model.APIResponse{Success: false, Error: "file path must be relative"})
		return
	}

	dirAbs, err := h.secureWorkspacePath(dir)
	if err != nil {
		respondPathScopeError(c, err)
		return
	}
	fullPath, err := h.secureChildPath(dirAbs, filePath)
	if err != nil {
		respondPathScopeError(c, err)
		return
	}

	data, err := h.runner.BrowseFile(fullPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: map[string]interface{}{
		"path":    fullPath,
		"content": string(data),
	}})
}

func (h *APKHandler) secureWorkspacePath(path string) (string, error) {
	workspaceAbs, err := workspaceRootAbs(h.cfg)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	if err := ensurePathInside(workspaceAbs, abs); err != nil {
		return "", err
	}
	return abs, nil
}

func (h *APKHandler) secureChildPath(parentAbs, childRel string) (string, error) {
	if childRel == "" || filepath.IsAbs(childRel) {
		return "", errPathOutsideWorkspace
	}
	fullPath, err := filepath.Abs(filepath.Join(parentAbs, childRel))
	if err != nil {
		return "", err
	}
	if err := ensurePathInside(parentAbs, fullPath); err != nil {
		return "", err
	}
	workspaceAbs, err := workspaceRootAbs(h.cfg)
	if err != nil {
		return "", err
	}
	if err := ensurePathInside(workspaceAbs, fullPath); err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(fullPath); err == nil {
		if err := ensurePathInside(parentAbs, real); err != nil {
			return "", err
		}
		if err := ensurePathInside(workspaceAbs, real); err != nil {
			return "", err
		}
	}
	return fullPath, nil
}

var errPathOutsideWorkspace = errors.New("path outside workspace")

func workspaceRootAbs(cfg *config.Config) (string, error) {
	if cfg == nil || strings.TrimSpace(cfg.Storage.WorkspaceDir) == "" {
		return "", errors.New("workspace_dir not configured")
	}
	workspaceAbs, err := filepath.Abs(cfg.Storage.WorkspaceDir)
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(workspaceAbs); err == nil {
		workspaceAbs = real
	}
	return workspaceAbs, nil
}

func ensurePathInside(baseAbs, pathAbs string) error {
	rel, err := filepath.Rel(baseAbs, pathAbs)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return errPathOutsideWorkspace
	}
	return nil
}

func respondPathScopeError(c *gin.Context, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, errPathOutsideWorkspace) {
		status = http.StatusForbidden
	}
	c.JSON(status, model.APIResponse{Success: false, Error: err.Error()})
}

// Build compiles an APK from source directory
func (h *APKHandler) Build(c *gin.Context) {
	var req struct {
		SourceDir   string `json:"source_dir"`
		ProjectPath string `json:"project_path"`
		OutputDir   string `json:"output_dir"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if req.SourceDir == "" {
		req.SourceDir = req.ProjectPath
	}
	if req.SourceDir == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "source_dir required"})
		return
	}

	result, err := h.runner.Build(req.SourceDir, req.OutputDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: map[string]string{"output_path": result}})
}

// Sign signs an APK file
func (h *APKHandler) Sign(c *gin.Context) {
	var req struct {
		ApkPath      string `json:"apk_path"`
		KeystorePath string `json:"keystore_path"`
		KeyAlias     string `json:"key_alias"`
		StorePass    string `json:"store_pass"`
		KeyPass      string `json:"key_pass"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if req.ApkPath == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "apk_path required"})
		return
	}

	result, err := h.runner.Sign(req.ApkPath, runner.SignOptions{
		KeystorePath: req.KeystorePath,
		KeyAlias:     req.KeyAlias,
		StorePass:    req.StorePass,
		KeyPass:      req.KeyPass,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: map[string]string{"signed_path": result, "output_path": result}})
}

// InstallByPath installs an APK from file path to a device
func (h *APKHandler) InstallByPath(c *gin.Context) {
	var req struct {
		ApkPath string `json:"apk_path"`
		Serial  string `json:"serial"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	if req.ApkPath == "" || req.Serial == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "apk_path and serial required"})
		return
	}

	result, err := h.runner.InstallToDevice(req.Serial, req.ApkPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: map[string]string{"result": result}})
}

func getIntParam(c *gin.Context, key string, defaultVal int) int {
	s := c.DefaultQuery(key, strconv.Itoa(defaultVal))
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return v
}

// ─────────────── Analyzer endpoints ───────────────

func (h *APKHandler) resolveAPK(c *gin.Context) (*model.APK, bool) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "id required"})
		return nil, false
	}
	apk, err := h.store.Get(id)
	if err != nil || apk == nil {
		c.JSON(http.StatusNotFound, model.APIResponse{Success: false, Error: "APK not found"})
		return nil, false
	}
	return apk, true
}

func (h *APKHandler) saveAnalysis(apkID, typ string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return h.store.UpsertAnalysis(&model.APKAnalysis{
		ID:        util.NewID(),
		APKID:     apkID,
		Type:      typ,
		Result:    string(raw),
		CreatedAt: time.Now(),
	})
}

func (h *APKHandler) AnalyzeManifest(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	res, err := analyzer.ParseManifest(apk.FilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if res.Package != "" {
		apk.PackageName = res.Package
	}
	if res.VersionName != "" {
		apk.VersionName = res.VersionName
	}
	if res.VersionCode != 0 {
		apk.VersionCode = res.VersionCode
	}
	if res.MinSDK != 0 {
		apk.MinSDK = res.MinSDK
	}
	if res.TargetSDK != 0 {
		apk.TargetSDK = res.TargetSDK
	}
	_ = h.store.Update(apk)
	if err := h.saveAnalysis(apk.ID, analyzer.TypeManifest, res); err != nil {
		zap.L().Warn("save manifest analysis", zap.Error(err))
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: res})
}

func (h *APKHandler) AnalyzeCertificate(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	res, err := analyzer.ParseCertificate(apk.FilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if err := h.saveAnalysis(apk.ID, analyzer.TypeCertificate, res); err != nil {
		zap.L().Warn("save certificate analysis", zap.Error(err))
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: res})
}

func (h *APKHandler) AnalyzeRisk(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	manifest := h.loadCachedManifest(apk.ID)
	if manifest == nil {
		m, err := analyzer.ParseManifest(apk.FilePath)
		if err == nil {
			manifest = m
			_ = h.saveAnalysis(apk.ID, analyzer.TypeManifest, manifest)
		}
	}
	cert := h.loadCachedCertificate(apk.ID)
	if cert == nil {
		c2, err := analyzer.ParseCertificate(apk.FilePath)
		if err == nil {
			cert = c2
			_ = h.saveAnalysis(apk.ID, analyzer.TypeCertificate, cert)
		}
	}
	res := analyzer.EvaluateRisk(manifest, cert)
	if err := h.saveAnalysis(apk.ID, analyzer.TypeRisk, res); err != nil {
		zap.L().Warn("save risk analysis", zap.Error(err))
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: res})
}

func (h *APKHandler) AnalyzeAttackSurface(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	manifest := h.loadCachedManifest(apk.ID)
	if manifest == nil {
		m, err := analyzer.ParseManifest(apk.FilePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
			return
		}
		manifest = m
		_ = h.saveAnalysis(apk.ID, analyzer.TypeManifest, manifest)
	}
	res := analyzer.AnalyzeAttackSurface(manifest)
	if err := h.saveAnalysis(apk.ID, analyzer.TypeAttackSurface, res); err != nil {
		zap.L().Warn("save attack surface analysis", zap.Error(err))
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: res})
}

func (h *APKHandler) AnalyzeEntryTrace(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	if apk.DecompiledPath == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "decompile the APK first"})
		return
	}
	component := c.Query("component")
	var req struct {
		Component string `json:"component"`
	}
	if c.Request.Body != nil {
		_ = c.ShouldBindJSON(&req)
		if component == "" {
			component = req.Component
		}
	}
	manifest := h.loadCachedManifest(apk.ID)
	if manifest == nil {
		m, err := analyzer.ParseManifest(apk.FilePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
			return
		}
		manifest = m
		_ = h.saveAnalysis(apk.ID, analyzer.TypeManifest, manifest)
	}
	res, err := analyzer.AnalyzeEntryTrace(manifest, apk.DecompiledPath, component)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if err := h.saveAnalysis(apk.ID, analyzer.TypeEntryTrace, res); err != nil {
		zap.L().Warn("save entry trace analysis", zap.Error(err))
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: res})
}

func (h *APKHandler) AnalyzeCode(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	if apk.DecompiledPath == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "decompile the APK first"})
		return
	}
	res, err := analyzer.ScanCode(apk.DecompiledPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if err := h.saveAnalysis(apk.ID, analyzer.TypeCode, res); err != nil {
		zap.L().Warn("save code analysis", zap.Error(err))
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: res})
}

func (h *APKHandler) AnalyzeSDK(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	if apk.DecompiledPath == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "decompile the APK first"})
		return
	}
	res, err := analyzer.DetectSDKs(apk.DecompiledPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if err := h.saveAnalysis(apk.ID, analyzer.TypeSDK, res); err != nil {
		zap.L().Warn("save sdk analysis", zap.Error(err))
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: res})
}

func (h *APKHandler) AnalyzeAll(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	out := map[string]any{}

	if m, err := analyzer.ParseManifest(apk.FilePath); err == nil {
		out[analyzer.TypeManifest] = m
		if m.Package != "" {
			apk.PackageName = m.Package
		}
		if m.VersionName != "" {
			apk.VersionName = m.VersionName
		}
		if m.VersionCode != 0 {
			apk.VersionCode = m.VersionCode
		}
		if m.MinSDK != 0 {
			apk.MinSDK = m.MinSDK
		}
		if m.TargetSDK != 0 {
			apk.TargetSDK = m.TargetSDK
		}
		_ = h.store.Update(apk)
		_ = h.saveAnalysis(apk.ID, analyzer.TypeManifest, m)
	} else {
		out["manifest_error"] = err.Error()
	}

	if c2, err := analyzer.ParseCertificate(apk.FilePath); err == nil {
		out[analyzer.TypeCertificate] = c2
		_ = h.saveAnalysis(apk.ID, analyzer.TypeCertificate, c2)
	} else {
		out["certificate_error"] = err.Error()
	}

	manifest, _ := out[analyzer.TypeManifest].(*analyzer.ManifestResult)
	cert, _ := out[analyzer.TypeCertificate].(*analyzer.CertificateResult)
	risk := analyzer.EvaluateRisk(manifest, cert)
	out[analyzer.TypeRisk] = risk
	_ = h.saveAnalysis(apk.ID, analyzer.TypeRisk, risk)
	if manifest != nil {
		attackSurface := analyzer.AnalyzeAttackSurface(manifest)
		out[analyzer.TypeAttackSurface] = attackSurface
		_ = h.saveAnalysis(apk.ID, analyzer.TypeAttackSurface, attackSurface)
	} else {
		out["attack_surface_skipped"] = "manifest unavailable"
	}

	if apk.DecompiledPath != "" {
		if manifest != nil {
			if et, err := analyzer.AnalyzeEntryTrace(manifest, apk.DecompiledPath, ""); err == nil {
				out[analyzer.TypeEntryTrace] = et
				_ = h.saveAnalysis(apk.ID, analyzer.TypeEntryTrace, et)
			}
		}
		if pr, err := analyzer.DetectPacker(apk.FilePath, apk.DecompiledPath); err == nil {
			out[analyzer.TypePacker] = pr
			_ = h.saveAnalysis(apk.ID, analyzer.TypePacker, pr)
		}
		if cr, err := analyzer.ScanCode(apk.DecompiledPath); err == nil {
			out[analyzer.TypeCode] = cr
			_ = h.saveAnalysis(apk.ID, analyzer.TypeCode, cr)
		}
		if sr, err := analyzer.DetectSDKs(apk.DecompiledPath); err == nil {
			out[analyzer.TypeSDK] = sr
			_ = h.saveAnalysis(apk.ID, analyzer.TypeSDK, sr)
		}
		if sr, err := analyzer.ScanStrings(apk.DecompiledPath); err == nil {
			out[analyzer.TypeStrings] = sr
			_ = h.saveAnalysis(apk.ID, analyzer.TypeStrings, sr)
		}
		if ad, err := analyzer.DetectAntiDetection(apk.DecompiledPath); err == nil {
			out[analyzer.TypeAntiDetect] = ad
			_ = h.saveAnalysis(apk.ID, analyzer.TypeAntiDetect, ad)
		}
	} else {
		out["packer_skipped"] = "decompile required"
		out["code_skipped"] = "decompile required"
		out["sdk_skipped"] = "decompile required"
		out["strings_skipped"] = "decompile required"
		out["antidetect_skipped"] = "decompile required"
	}

	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: out})
}

// AnalyzeTriage runs the same reverse-engineering triage used by the LLM
// apk_triage skill, exposed as an HTTP API for the frontend and automation.
func (h *APKHandler) AnalyzeTriage(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	includeCallgraph := strings.EqualFold(c.Query("include_callgraph"), "true") || c.Query("include_callgraph") == "1"
	var req struct {
		IncludeCallgraph bool `json:"include_callgraph"`
	}
	if c.Request.Body != nil {
		_ = c.ShouldBindJSON(&req)
		includeCallgraph = includeCallgraph || req.IncludeCallgraph
	}
	result, err := agent.RunAPKTriage(h.store, h.cfg, apk.ID, includeCallgraph)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if err := h.saveAnalysis(apk.ID, analyzer.TypeTriage, result); err != nil {
		zap.L().Warn("save triage analysis", zap.Error(err))
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: result})
}

// RuntimePlan builds a non-executing dynamic validation plan from entry_trace
// flows, ADB replay commands, generated Frida hooks, and ready-to-run Frida
// arguments. It intentionally does not touch devices.
func (h *APKHandler) RuntimePlan(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	serial := c.Query("serial")
	var req struct {
		Serial string `json:"serial"`
	}
	if c.Request.Body != nil {
		_ = c.ShouldBindJSON(&req)
		if serial == "" {
			serial = req.Serial
		}
	}
	result, err := agent.RunAPKRuntimePlan(h.store, h.cfg, apk.ID, serial)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(strings.ToLower(err.Error()), "decompiled") || strings.Contains(strings.ToLower(err.Error()), "decompile") {
			status = http.StatusBadRequest
		}
		c.JSON(status, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if err := h.saveAnalysis(apk.ID, analyzer.TypeRuntimePlan, result); err != nil {
		zap.L().Warn("save runtime plan analysis", zap.Error(err))
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: result})
}

// ReversePlan builds a structured reverse-engineering checklist from
// persisted triage/runtime analyses. It does not touch devices.
func (h *APKHandler) ReversePlan(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	result, err := agent.RunAPKReversePlan(h.store, h.cfg, apk.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if err := h.saveAnalysis(apk.ID, analyzer.TypeReversePlan, result); err != nil {
		zap.L().Warn("save reverse plan analysis", zap.Error(err))
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: result})
}

// ReverseValidate checks the reverse plan against runtime evidence and
// returns remaining validation gaps.
func (h *APKHandler) ReverseValidate(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	result, err := agent.RunAPKReverseValidate(h.store, h.cfg, apk.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: result})
}

func (h *APKHandler) ListAnalyses(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	rows, err := h.store.ListAnalysis(apk.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	out := map[string]any{}
	for _, r := range rows {
		var v any
		if json.Unmarshal([]byte(r.Result), &v) == nil {
			typ := r.Type
			if typ == analyzer.TypeAntiDetectLegacy {
				typ = analyzer.TypeAntiDetect
			}
			out[typ] = v
		}
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: out})
}

func (h *APKHandler) loadCachedManifest(apkID string) *analyzer.ManifestResult {
	row, _ := h.store.GetAnalysisByType(apkID, analyzer.TypeManifest)
	if row == nil {
		return nil
	}
	var m analyzer.ManifestResult
	if json.Unmarshal([]byte(row.Result), &m) != nil {
		return nil
	}
	return &m
}

func (h *APKHandler) loadCachedCertificate(apkID string) *analyzer.CertificateResult {
	row, _ := h.store.GetAnalysisByType(apkID, analyzer.TypeCertificate)
	if row == nil {
		return nil
	}
	var c analyzer.CertificateResult
	if json.Unmarshal([]byte(row.Result), &c) != nil {
		return nil
	}
	return &c
}

// GenerateReport produces a full security report for an APK.
func (h *APKHandler) GenerateReport(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	report, err := analyzer.GenerateReport(apk.FilePath, apk.DecompiledPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	if row, _ := h.store.GetAnalysisByType(apk.ID, analyzer.TypeRuntimeEvidence); row != nil {
		if summary, details, ok := analyzer.SummarizeRuntimeEvidenceJSON(row.Result, 10); ok {
			if planRow, _ := h.store.GetAnalysisByType(apk.ID, analyzer.TypeRuntimePlan); planRow != nil {
				if verified := analyzer.RuntimeEvidenceVerifiedFlows(summary, planRow.Result, 10); len(verified) > 0 {
					summary["verified_flows"] = verified
				}
			}
			report.Sections = append(report.Sections, analyzer.RuntimeEvidenceReportSection(summary, details))
		}
	}
	format := c.Query("format")
	if format == "text" {
		c.String(http.StatusOK, analyzer.FormatReportText(report))
		return
	}
	_ = h.saveAnalysis(apk.ID, analyzer.TypeReport, report)
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: report})
}

func (h *APKHandler) EvidencePackage(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	pkg := h.buildEvidencePackage(apk)
	if c.Query("format") == "markdown" || c.Query("format") == "md" {
		c.String(http.StatusOK, pkg["markdown"].(string))
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: pkg})
}

func (h *APKHandler) buildEvidencePackage(apk *model.APK) map[string]any {
	out := map[string]any{
		"apk": map[string]any{
			"id":              apk.ID,
			"filename":        apk.Filename,
			"package_name":    apk.PackageName,
			"version_name":    apk.VersionName,
			"version_code":    apk.VersionCode,
			"file_path":       apk.FilePath,
			"decompiled_path": apk.DecompiledPath,
			"decompiled_tool": apk.DecompiledTool,
		},
	}
	var runtimePlan map[string]any
	if row, _ := h.store.GetAnalysisByType(apk.ID, analyzer.TypeRuntimePlan); row != nil {
		_ = json.Unmarshal([]byte(row.Result), &runtimePlan)
		if runtimePlan != nil {
			out["runtime_plan"] = runtimePlan
		}
	}
	if row, _ := h.store.GetAnalysisByType(apk.ID, analyzer.TypeRuntimeEvidence); row != nil {
		if summary, details, ok := analyzer.SummarizeRuntimeEvidenceJSON(row.Result, 20); ok {
			if runtimePlan != nil {
				if verified := analyzer.RuntimeEvidenceVerifiedFlows(summary, rowString(runtimePlan), 20); len(verified) > 0 {
					summary["verified_flows"] = verified
				}
			}
			out["runtime_evidence"] = summary
			out["evidence_details"] = details
			var raw map[string]any
			if json.Unmarshal([]byte(row.Result), &raw) == nil {
				out["runtime_evidence_raw"] = raw
			}
		}
	}
	if row, _ := h.store.GetAnalysisByType(apk.ID, analyzer.TypeEntryTrace); row != nil {
		var entryTrace map[string]any
		if json.Unmarshal([]byte(row.Result), &entryTrace) == nil {
			out["entry_trace"] = entryTrace
		}
	}
	out["markdown"] = formatEvidencePackageMarkdown(out)
	return out
}

func rowString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func formatEvidencePackageMarkdown(pkg map[string]any) string {
	apk := asMap(pkg["apk"])
	runtimeEvidence := asMap(pkg["runtime_evidence"])
	runtimePlan := asMap(pkg["runtime_plan"])
	var b strings.Builder
	fmt.Fprintf(&b, "# APK Runtime Evidence Package\n\n")
	fmt.Fprintf(&b, "## Target\n\n")
	fmt.Fprintf(&b, "- APK ID: `%v`\n", apk["id"])
	fmt.Fprintf(&b, "- File: `%v`\n", apk["filename"])
	fmt.Fprintf(&b, "- Package: `%v`\n", apk["package_name"])
	fmt.Fprintf(&b, "- Decompiled: `%v` `%v`\n\n", apk["decompiled_tool"], apk["decompiled_path"])
	if len(runtimeEvidence) > 0 {
		fmt.Fprintf(&b, "## Runtime Evidence Summary\n\n")
		fmt.Fprintf(&b, "- ENTRY_TRACE hits: `%v`\n", runtimeEvidence["entry_trace"])
		fmt.Fprintf(&b, "- Hook: `%v`\n", runtimeEvidence["hook_id"])
		fmt.Fprintf(&b, "- Flow IDs: `%s`\n\n", strings.Join(asStringList(runtimeEvidence["flow_ids"]), "`, `"))
		if verified := asList(runtimeEvidence["verified_flows"]); len(verified) > 0 {
			fmt.Fprintf(&b, "## Verified Flows\n\n")
			for _, raw := range verified {
				flow := asMap(raw)
				source := asMap(flow["source"])
				sink := asMap(flow["sink"])
				fmt.Fprintf(&b, "### %v\n\n", flow["flow_id"])
				fmt.Fprintf(&b, "- Component: `%v`\n", flow["component"])
				fmt.Fprintf(&b, "- Method: `%v`\n", flow["method"])
				fmt.Fprintf(&b, "- File: `%v`\n", flow["file"])
				fmt.Fprintf(&b, "- Source: `%v` line `%v`\n", source["kind"], source["line"])
				fmt.Fprintf(&b, "- Sink: `%v` `%v` line `%v`\n", sink["kind"], sink["pattern"], sink["line"])
				if vars := asStringList(flow["variables"]); len(vars) > 0 {
					fmt.Fprintf(&b, "- Variables: `%s`\n", strings.Join(vars, "`, `"))
				}
				for _, evRaw := range asList(flow["hit_events"]) {
					ev := asMap(evRaw)
					fmt.Fprintf(&b, "- Runtime hit: `[%v] %v` — `%v`\n", ev["kind"], ev["operation"], ev["value"])
				}
				b.WriteString("\n")
			}
		}
	}
	if replay := asStringList(runtimePlan["adb_replay"]); len(replay) > 0 {
		fmt.Fprintf(&b, "## ADB Replay Commands\n\n")
		for _, cmd := range replay {
			fmt.Fprintf(&b, "```bash\n%s\n```\n\n", cmd)
		}
	}
	if hooks := asList(runtimePlan["generated_hooks"]); len(hooks) > 0 {
		fmt.Fprintf(&b, "## Generated Hooks\n\n")
		for _, rawHook := range hooks {
			hook := asMap(rawHook)
			fmt.Fprintf(&b, "### %v\n\n", hook["id"])
			fmt.Fprintf(&b, "- Name: %v\n", hook["name"])
			fmt.Fprintf(&b, "- Flow IDs: `%s`\n\n", strings.Join(asStringList(hook["flow_ids"]), "`, `"))
		}
	}
	if details := asStringList(pkg["evidence_details"]); len(details) > 0 {
		fmt.Fprintf(&b, "## Runtime Event Details\n\n")
		for _, d := range details {
			fmt.Fprintf(&b, "- %s\n", d)
		}
	}
	return b.String()
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func asList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	if l, ok := v.([]map[string]any); ok {
		out := make([]any, 0, len(l))
		for _, item := range l {
			out = append(out, item)
		}
		return out
	}
	return nil
}

func asStringList(v any) []string {
	if l, ok := v.([]string); ok {
		return l
	}
	out := []string{}
	for _, item := range asList(v) {
		if s := fmt.Sprint(item); s != "" && s != "<nil>" {
			out = append(out, s)
		}
	}
	return out
}

// DetectPacker checks for known Android app protectors/packers.
func (h *APKHandler) DetectPacker(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	result, err := analyzer.DetectPacker(apk.FilePath, apk.DecompiledPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	_ = h.saveAnalysis(apk.ID, analyzer.TypePacker, result)
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: result})
}

func (h *APKHandler) ScanStrings(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	result, err := analyzer.ScanStrings(apk.DecompiledPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	_ = h.saveAnalysis(apk.ID, analyzer.TypeStrings, result)
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: result})
}

func (h *APKHandler) DiffAPKs(c *gin.Context) {
	oldID := c.Query("old")
	newID := c.Query("new")
	if oldID == "" || newID == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "both 'old' and 'new' query params required"})
		return
	}
	oldAPK, err := h.store.Get(oldID)
	if err != nil {
		c.JSON(http.StatusNotFound, model.APIResponse{Success: false, Error: "old APK not found"})
		return
	}
	newAPK, err := h.store.Get(newID)
	if err != nil {
		c.JSON(http.StatusNotFound, model.APIResponse{Success: false, Error: "new APK not found"})
		return
	}
	if oldAPK.DecompiledPath == "" || newAPK.DecompiledPath == "" {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "both APKs must be decompiled first"})
		return
	}
	result, err := analyzer.DiffAPKs(oldAPK.DecompiledPath, newAPK.DecompiledPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: result})
}

func (h *APKHandler) DetectAntiDetection(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	result, err := analyzer.DetectAntiDetection(apk.DecompiledPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	_ = h.saveAnalysis(apk.ID, analyzer.TypeAntiDetect, result)
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: result})
}

func (h *APKHandler) GenerateHooks(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}

	antiDetect, _ := analyzer.DetectAntiDetection(apk.DecompiledPath)
	stringsResult, _ := analyzer.ScanStrings(apk.DecompiledPath)

	var cryptoFindings []analyzer.CryptoFinding
	if stringsResult != nil {
		cryptoFindings = stringsResult.CryptoUsage
	}

	var entryTrace *analyzer.EntryTraceResult
	if apk.DecompiledPath != "" {
		manifest := h.loadCachedManifest(apk.ID)
		if manifest == nil {
			if m, err := analyzer.ParseManifest(apk.FilePath); err == nil {
				manifest = m
				_ = h.saveAnalysis(apk.ID, analyzer.TypeManifest, manifest)
			}
		}
		if manifest != nil {
			if et, err := analyzer.AnalyzeEntryTrace(manifest, apk.DecompiledPath, ""); err == nil {
				entryTrace = et
				_ = h.saveAnalysis(apk.ID, analyzer.TypeEntryTrace, et)
			}
		}
	}

	hooks := frida.GenerateHooksFromAnalysis(antiDetect, cryptoFindings, stringsResult, entryTrace)
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: gin.H{
		"hooks": hooks,
		"count": len(hooks),
	}})
}

func (h *APKHandler) ParseNetworkCapture(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, model.APIResponse{Success: false, Error: "file is required"})
		return
	}

	tmpDir := filepath.Join(h.cfg.Storage.WorkspaceDir, "network")
	os.MkdirAll(tmpDir, 0o755)
	tmpPath := filepath.Join(tmpDir, file.Filename)
	if err := c.SaveUploadedFile(file, tmpPath); err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: "failed to save file"})
		return
	}
	defer os.Remove(tmpPath)

	result, err := analyzer.ParseNetworkCapture(tmpPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: result})
}

func (h *APKHandler) CallGraph(c *gin.Context) {
	apk, ok := h.resolveAPK(c)
	if !ok {
		return
	}
	targetPkg := c.Query("package")
	result, err := analyzer.BuildCallGraph(apk.DecompiledPath, targetPkg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.APIResponse{Success: false, Error: err.Error()})
		return
	}
	_ = h.saveAnalysis(apk.ID, analyzer.TypeCallGraph, result)
	c.JSON(http.StatusOK, model.APIResponse{Success: true, Data: result})
}
