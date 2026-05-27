package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/mobileagent/backend-go/internal/config"
	"github.com/mobileagent/backend-go/internal/model"
	"github.com/mobileagent/backend-go/internal/util"
)

type APKRunner struct {
	cfg *config.Config
}

type SignOptions struct {
	KeystorePath string
	KeyAlias     string
	StorePass    string
	KeyPass      string
}

func NewAPKRunner(cfg *config.Config) *APKRunner {
	return &APKRunner{cfg: cfg}
}

func (r *APKRunner) Analyze(apk *model.APK) (*model.APKAnalysis, error) {
	analysis := &model.APKAnalysis{
		ID:    util.NewID(),
		APKID: apk.ID,
		Type:  "full",
	}

	pkgName, verName, verCode, err := r.parseAAPT(apk.FilePath)
	if err != nil {
		zap.L().Warn("aapt parse failed", zap.Error(err))
	} else {
		apk.PackageName = pkgName
		apk.VersionName = verName
		apk.VersionCode = verCode
	}

	analysis.Result = fmt.Sprintf("package=%s version=%s", pkgName, verName)
	return analysis, nil
}

func (r *APKRunner) Decompile(apkPath, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}
	cmd := exec.Command(r.cfg.Tools.APKTool, "d", "-f", "-o", outputDir, apkPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("apktool decompile: %w\n%s", err, string(out))
	}
	return outputDir, nil
}

func (r *APKRunner) DecompileWithJADX(apkPath, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}
	cmd := exec.Command(r.cfg.Tools.JADX, "-d", outputDir, apkPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("jadx decompile: %w\n%s", err, string(out))
	}
	return outputDir, nil
}

func (r *APKRunner) InstallToDevice(serial, apkPath string) (string, error) {
	return util.InstallAPK(r.cfg.ADB.Path, serial, apkPath)
}

func (r *APKRunner) UninstallFromDevice(serial, pkg string) (string, error) {
	return util.UninstallApp(r.cfg.ADB.Path, serial, pkg)
}

func (r *APKRunner) parseAAPT(apkPath string) (pkgName, verName string, verCode int, err error) {
	cmd := exec.Command("aapt", "dump", "badging", apkPath)
	out, e := cmd.CombinedOutput()
	if e != nil {
		err = e
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "package: name=") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.HasPrefix(p, "name='") {
					pkgName = strings.TrimPrefix(p, "name='")
					pkgName = strings.TrimSuffix(pkgName, "'")
				}
				if strings.HasPrefix(p, "versionName='") {
					verName = strings.TrimPrefix(p, "versionName='")
					verName = strings.TrimSuffix(verName, "'")
				}
			}
			break
		}
	}
	return
}

func (r *APKRunner) SaveUploadedFile(filename string, data []byte) (string, error) {
	uploadDir := r.cfg.Storage.UploadDir
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		return "", fmt.Errorf("create upload dir: %w", err)
	}
	dstPath := filepath.Join(uploadDir, fmt.Sprintf("%s_%s", util.NewID()[:8], filename))
	if err := os.WriteFile(dstPath, data, 0644); err != nil {
		return "", fmt.Errorf("write file: %w", err)
	}
	return dstPath, nil
}

// BrowseFile reads a file from the decompiled APK directory
func (r *APKRunner) BrowseFile(fullPath string) ([]byte, error) {
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return data, nil
}

// Build compiles an APK from source directory using apktool
func (r *APKRunner) Build(sourceDir, outputDir string) (string, error) {
	if outputDir == "" {
		outputDir = r.cfg.Storage.WorkspaceDir
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}
	outputAPK := filepath.Join(outputDir, util.NewID()[:8]+".apk")
	cmd := exec.Command(r.cfg.Tools.APKTool, "b", "-o", outputAPK, sourceDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("apktool build: %w\n%s", err, string(out))
	}
	return outputAPK, nil
}

// Sign signs an APK with a debug key by default, or with a provided keystore
// when keystore options are supplied. It returns the actual generated artifact
// path instead of guessing a suffix.
func (r *APKRunner) Sign(apkPath string, opts SignOptions) (string, error) {
	if strings.TrimSpace(apkPath) == "" {
		return "", fmt.Errorf("apk_path required")
	}
	if info, err := os.Stat(apkPath); err != nil {
		return "", fmt.Errorf("stat apk: %w", err)
	} else if info.IsDir() {
		return "", fmt.Errorf("apk_path points to a directory")
	}
	if opts.KeystorePath != "" {
		if _, err := os.Stat(opts.KeystorePath); err != nil {
			return "", fmt.Errorf("stat keystore: %w", err)
		}
		if opts.KeyAlias == "" {
			return "", fmt.Errorf("key_alias required when keystore_path is provided")
		}
	}

	outDir := filepath.Join(r.cfg.Storage.WorkspaceDir, "signed", util.NewID()[:8])
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", fmt.Errorf("create signing output dir: %w", err)
	}

	if signer, ok := executablePath(r.cfg.Tools.UberApkSigner, "uber-apk-signer"); ok {
		return r.signWithUberApkSigner(signer, apkPath, outDir, opts)
	}
	return r.signWithAPKSig(apkPath, outDir, opts)
}

func (r *APKRunner) signWithUberApkSigner(signer, apkPath, outDir string, opts SignOptions) (string, error) {
	args := []string{"-a", apkPath, "-o", outDir, "--allowResign"}
	if zipalign, ok := executablePath(r.cfg.Tools.Zipalign, "zipalign"); ok {
		args = append(args, "--zipAlignPath", zipalign)
	}
	if opts.KeystorePath != "" {
		args = append(args, "--ks", opts.KeystorePath, "--ksAlias", opts.KeyAlias)
		if opts.StorePass != "" {
			args = append(args, "--ksPass", opts.StorePass)
		}
		if opts.KeyPass != "" {
			args = append(args, "--ksKeyPass", opts.KeyPass)
		}
	}

	out, err := runAPKTool(5*time.Minute, signer, args...)
	if err != nil {
		return "", fmt.Errorf("uber-apk-signer: %w\n%s", err, string(out))
	}
	signed, err := newestAPK(outDir)
	if err != nil {
		return "", fmt.Errorf("locate signed APK: %w\n%s", err, string(out))
	}
	return signed, nil
}

func (r *APKRunner) signWithAPKSig(apkPath, outDir string, opts SignOptions) (string, error) {
	apksigner, ok := executablePath(r.cfg.Tools.APKSigner, "apksigner")
	if !ok {
		return "", fmt.Errorf("no signer found: configure tools.uber_apk_signer or tools.apksigner")
	}

	inputPath := apkPath
	if zipalign, ok := executablePath(r.cfg.Tools.Zipalign, "zipalign"); ok {
		alignedPath := filepath.Join(outDir, strings.TrimSuffix(filepath.Base(apkPath), ".apk")+"-aligned.apk")
		out, err := runAPKTool(2*time.Minute, zipalign, "-f", "-p", "4", apkPath, alignedPath)
		if err != nil {
			return "", fmt.Errorf("zipalign: %w\n%s", err, string(out))
		}
		inputPath = alignedPath
	}

	keystorePath := opts.KeystorePath
	keyAlias := opts.KeyAlias
	storePass := opts.StorePass
	keyPass := opts.KeyPass
	if keystorePath == "" {
		var err error
		keystorePath, err = r.ensureDebugKeystore(outDir)
		if err != nil {
			return "", err
		}
		keyAlias = "androiddebugkey"
		storePass = "android"
		keyPass = "android"
	}

	signedPath := filepath.Join(outDir, strings.TrimSuffix(filepath.Base(apkPath), ".apk")+"-signed.apk")
	args := []string{"sign", "--ks", keystorePath, "--ks-key-alias", keyAlias, "--out", signedPath}
	if storePass != "" {
		args = append(args, "--ks-pass", "pass:"+storePass)
	}
	if keyPass != "" {
		args = append(args, "--key-pass", "pass:"+keyPass)
	}
	args = append(args, inputPath)

	out, err := runAPKTool(5*time.Minute, apksigner, args...)
	if err != nil {
		return "", fmt.Errorf("apksigner: %w\n%s", err, string(out))
	}
	return signedPath, nil
}

func (r *APKRunner) ensureDebugKeystore(outDir string) (string, error) {
	ksPath := filepath.Join(outDir, "debug.keystore")
	keytool, err := exec.LookPath("keytool")
	if err != nil {
		return "", fmt.Errorf("keytool not found for debug keystore generation: %w", err)
	}
	args := []string{
		"-genkeypair",
		"-keystore", ksPath,
		"-storepass", "android",
		"-keypass", "android",
		"-alias", "androiddebugkey",
		"-keyalg", "RSA",
		"-keysize", "2048",
		"-validity", "10000",
		"-dname", "CN=Android Debug,O=Android,C=US",
	}
	out, err := runAPKTool(2*time.Minute, keytool, args...)
	if err != nil {
		return "", fmt.Errorf("generate debug keystore: %w\n%s", err, string(out))
	}
	return ksPath, nil
}

func executablePath(configured, name string) (string, bool) {
	if configured != "" {
		if info, err := os.Stat(configured); err == nil && !info.IsDir() {
			return configured, true
		}
	}
	if found, err := exec.LookPath(name); err == nil {
		return found, true
	}
	return "", false
}

func runAPKTool(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader("")
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("command timed out after %s", timeout)
	}
	return out, err
}

func newestAPK(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var newest string
	var newestTime time.Time
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".apk") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if newest == "" || info.ModTime().After(newestTime) {
			newest = filepath.Join(dir, entry.Name())
			newestTime = info.ModTime()
		}
	}
	if newest == "" {
		return "", fmt.Errorf("no APK generated in %s", dir)
	}
	return newest, nil
}
