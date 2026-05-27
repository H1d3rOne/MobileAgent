package analyzer

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const TypePacker = "packer"

type PackerSignature struct {
	Name     string   `json:"name"`
	Vendor   string   `json:"vendor"`
	Files    []string `json:"-"`
	Packages []string `json:"-"`
	Libs     []string `json:"-"`
}

type PackerResult struct {
	Detected    []DetectedPacker `json:"detected"`
	HasPacker   bool             `json:"has_packer"`
	MultiDex    bool             `json:"multi_dex"`
	DexCount    int              `json:"dex_count"`
	NativeLibs  []string         `json:"native_libs,omitempty"`
	Suggestions []string         `json:"suggestions,omitempty"`
}

type DetectedPacker struct {
	Name       string   `json:"name"`
	Vendor     string   `json:"vendor"`
	Confidence string   `json:"confidence"` // high, medium, low
	Evidence   []string `json:"evidence"`
}

var packerSignatures = []PackerSignature{
	{
		Name:     "360加固保",
		Vendor:   "Qihoo 360",
		Files:    []string{"libjiagu.so", "libjiagu_art.so", "libjiagu_x86.so"},
		Packages: []string{"com/qihoo/util", "com/qihoo360/replugin"},
		Libs:     []string{"libjiagu"},
	},
	{
		Name:     "腾讯乐固 (Tencent Legu)",
		Vendor:   "Tencent",
		Files:    []string{"libshell-super.2019.so", "libshella-", "libtxAppProtect.so", "libBugly.so"},
		Packages: []string{"com/tencent/StubShell", "com/tencent/bugly"},
		Libs:     []string{"libshell", "libtxApp", "libmain_dex"},
	},
	{
		Name:     "梆梆加固 (Bangcle)",
		Vendor:   "Bangcle",
		Files:    []string{"libsecexe.so", "libsecmain.so", "libDexHelper.so", "libSecShell.so"},
		Packages: []string{"com/secneo/apkwrapper", "com/bangcle"},
		Libs:     []string{"libsecexe", "libsecmain", "libDexHelper"},
	},
	{
		Name:     "爱加密 (iJiami)",
		Vendor:   "iJiami",
		Files:    []string{"libexec.so", "libexecmain.so", "ijiami.dat"},
		Packages: []string{"com/shell/SuperApplication", "com/ijiami"},
		Libs:     []string{"libexec", "libexecmain"},
	},
	{
		Name:     "娜迦加固 (Nagain/NAGA)",
		Vendor:   "Nagain",
		Files:    []string{"libchaosvmp.so", "libddog.so", "libfdog.so"},
		Packages: []string{"com/nagain"},
		Libs:     []string{"libchaosvmp", "libddog"},
	},
	{
		Name:     "百度加固",
		Vendor:   "Baidu",
		Files:    []string{"libbaiduprotect.so", "baiduprotect.jar"},
		Packages: []string{"com/baidu/protect"},
		Libs:     []string{"libbaiduprotect"},
	},
	{
		Name:     "阿里聚安全 (Ali)",
		Vendor:   "Alibaba",
		Files:    []string{"libmobisec.so", "libaliprotect.so", "aliprotect.dat"},
		Packages: []string{"com/alibaba/wireless/security", "com/alibaba/mobileim"},
		Libs:     []string{"libmobisec", "libaliprotect"},
	},
	{
		Name:     "网易易盾 (NetEase)",
		Vendor:   "NetEase",
		Files:    []string{"libnesec.so", "libNetHTProtect.so"},
		Packages: []string{"com/netease/nis", "com/netease/htprotect"},
		Libs:     []string{"libnesec", "libNetHTProtect"},
	},
	{
		Name:     "DexGuard",
		Vendor:   "Guardsquare",
		Files:    []string{"classes-v1.bin", "classes-v2.bin"},
		Packages: []string{"dexguard/"},
		Libs:     []string{},
	},
	{
		Name:     "DexProtector",
		Vendor:   "Licel",
		Files:    []string{"dp.arm.so.dat", "dp.arm-v7.so.dat", "dp.x86.so.dat"},
		Packages: []string{"dexprotector/"},
		Libs:     []string{},
	},
	{
		Name:     "APKProtect",
		Vendor:   "APKProtect",
		Files:    []string{"libAPKProtect.so"},
		Packages: []string{"com/apkprotect"},
		Libs:     []string{"libAPKProtect"},
	},
	{
		Name:     "通付盾 (Payegis)",
		Vendor:   "Payegis",
		Files:    []string{"libegis.so", "libNSaferOnly.so"},
		Packages: []string{"com/payegis"},
		Libs:     []string{"libegis"},
	},
	{
		Name:     "顶象 (Dingxiang)",
		Vendor:   "Dingxiang",
		Files:    []string{"libx3g.so"},
		Packages: []string{"com/dingxiang/mobile"},
		Libs:     []string{"libx3g"},
	},
	{
		Name:     "海云安 (Haiyunan)",
		Vendor:   "Haiyunan",
		Files:    []string{"libitsec.so"},
		Packages: []string{"com/itsec"},
		Libs:     []string{"libitsec"},
	},
	{
		Name:     "几维安全 (Kiwisec)",
		Vendor:   "Kiwisec",
		Files:    []string{"libkwscmm.so", "libkwscr.so", "libkwslinker.so"},
		Packages: []string{"com/kiwisec"},
		Libs:     []string{"libkwsc"},
	},
}

func DetectPacker(apkPath, decompiledPath string) (*PackerResult, error) {
	result := &PackerResult{}

	if decompiledPath == "" {
		return result, nil
	}

	allFiles := map[string]bool{}
	allDirs := map[string]bool{}
	dexCount := 0

	_ = filepath.WalkDir(decompiledPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(decompiledPath, path)
		if d.IsDir() {
			allDirs[filepath.ToSlash(rel)+"/"] = true
			return nil
		}
		name := d.Name()
		allFiles[name] = true
		allFiles[filepath.ToSlash(rel)] = true

		if strings.HasPrefix(name, "classes") && strings.HasSuffix(name, ".dex") {
			dexCount++
		}
		if strings.HasSuffix(name, ".so") {
			result.NativeLibs = append(result.NativeLibs, name)
		}
		return nil
	})

	result.DexCount = dexCount
	result.MultiDex = dexCount > 1

	for _, sig := range packerSignatures {
		evidence := []string{}

		for _, f := range sig.Files {
			if strings.Contains(f, "-") {
				for file := range allFiles {
					if strings.Contains(file, f) {
						evidence = append(evidence, "file: "+file)
					}
				}
			} else if allFiles[f] {
				evidence = append(evidence, "file: "+f)
			} else {
				for file := range allFiles {
					if strings.Contains(file, f) {
						evidence = append(evidence, "file: "+file)
						break
					}
				}
			}
		}

		for _, pkg := range sig.Packages {
			for dir := range allDirs {
				if strings.Contains(dir, pkg) {
					evidence = append(evidence, "package: "+dir)
					break
				}
			}
		}

		for _, lib := range sig.Libs {
			for file := range allFiles {
				if strings.HasSuffix(file, ".so") && strings.Contains(file, lib) {
					evidence = append(evidence, "native: "+file)
					break
				}
			}
		}

		if len(evidence) > 0 {
			confidence := "low"
			if len(evidence) >= 3 {
				confidence = "high"
			} else if len(evidence) >= 2 {
				confidence = "medium"
			}
			result.Detected = append(result.Detected, DetectedPacker{
				Name:       sig.Name,
				Vendor:     sig.Vendor,
				Confidence: confidence,
				Evidence:   dedupe(evidence),
			})
		}
	}

	result.HasPacker = len(result.Detected) > 0

	if result.HasPacker {
		result.Suggestions = []string{
			"Use frida to dump the original DEX at runtime",
			"Try FART (ART runtime DEX dump) for unpacking",
			"Check for anti-debug/anti-frida protections before hooking",
		}
	}

	if result.MultiDex && !result.HasPacker {
		entries, _ := os.ReadDir(filepath.Join(decompiledPath, "smali"))
		if len(entries) == 0 {
			result.Suggestions = append(result.Suggestions, "Smali directory is empty — APK may be packed with an unknown packer")
		}
	}

	return result, nil
}

func dedupe(ss []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
