package analyzer

import (
	"io/fs"
	"path/filepath"
	"strings"
)

type sdkSignature struct {
	Name     string
	Category string
	Prefixes []string
}

var sdkSignatures = []sdkSignature{
	{"Firebase", "google", []string{"com/google/firebase/"}},
	{"Google Play Services", "google", []string{"com/google/android/gms/"}},
	{"Google Mobile Ads (AdMob)", "ads", []string{"com/google/android/gms/ads/", "com/google/ads/"}},
	{"Google Analytics", "analytics", []string{"com/google/analytics/"}},
	{"Crashlytics", "crash", []string{"com/google/firebase/crashlytics/", "com/crashlytics/"}},
	{"Facebook SDK", "social", []string{"com/facebook/"}},
	{"Twitter SDK", "social", []string{"com/twitter/sdk/"}},
	{"WeChat SDK", "social", []string{"com/tencent/mm/", "com/tencent/wxop/"}},
	{"QQ SDK", "social", []string{"com/tencent/connect/"}},
	{"Weibo SDK", "social", []string{"com/sina/weibo/sdk/"}},
	{"Alipay", "payment", []string{"com/alipay/sdk/"}},
	{"WeChat Pay", "payment", []string{"com/tencent/mm/opensdk/modelpay/"}},
	{"Stripe", "payment", []string{"com/stripe/android/"}},
	{"PayPal", "payment", []string{"com/paypal/"}},
	{"Umeng", "analytics", []string{"com/umeng/"}},
	{"Baidu", "analytics", []string{"com/baidu/mobstat/", "com/baidu/location/"}},
	{"AppsFlyer", "analytics", []string{"com/appsflyer/"}},
	{"Adjust", "analytics", []string{"com/adjust/sdk/"}},
	{"Branch", "analytics", []string{"io/branch/referral/"}},
	{"Mixpanel", "analytics", []string{"com/mixpanel/android/"}},
	{"Flurry", "analytics", []string{"com/flurry/"}},
	{"Amplitude", "analytics", []string{"com/amplitude/"}},
	{"Sentry", "crash", []string{"io/sentry/"}},
	{"Bugly", "crash", []string{"com/tencent/bugly/"}},
	{"OkHttp", "network", []string{"okhttp3/", "com/squareup/okhttp/"}},
	{"Retrofit", "network", []string{"retrofit2/", "retrofit/"}},
	{"Volley", "network", []string{"com/android/volley/"}},
	{"Gson", "serialization", []string{"com/google/gson/"}},
	{"Jackson", "serialization", []string{"com/fasterxml/jackson/"}},
	{"Glide", "image", []string{"com/bumptech/glide/"}},
	{"Picasso", "image", []string{"com/squareup/picasso/"}},
	{"Fresco", "image", []string{"com/facebook/drawee/", "com/facebook/imagepipeline/"}},
	{"RxJava", "framework", []string{"io/reactivex/", "rx/"}},
	{"Dagger", "di", []string{"dagger/"}},
	{"Hilt", "di", []string{"dagger/hilt/"}},
	{"Koin", "di", []string{"org/koin/"}},
	{"Realm", "database", []string{"io/realm/"}},
	{"Room", "database", []string{"androidx/room/"}},
	{"Flutter", "framework", []string{"io/flutter/"}},
	{"React Native", "framework", []string{"com/facebook/react/"}},
	{"Cordova", "framework", []string{"org/apache/cordova/"}},
	{"Unity", "framework", []string{"com/unity3d/"}},
	{"Frida", "debug", []string{"re/frida/"}},
	{"OneSignal", "push", []string{"com/onesignal/"}},
	{"JPush", "push", []string{"cn/jpush/"}},
	{"Getui", "push", []string{"com/igexin/"}},
}

func DetectSDKs(decompiledDir string) (*SDKResult, error) {
	res := &SDKResult{}
	if decompiledDir == "" {
		return res, nil
	}
	dirs := map[string]bool{}
	roots := []string{
		filepath.Join(decompiledDir, "smali"),
		filepath.Join(decompiledDir, "sources"),
	}
	for _, base := range []string{decompiledDir} {
		entries, err := filepath.Glob(filepath.Join(base, "smali_classes*"))
		if err == nil {
			roots = append(roots, entries...)
		}
	}
	for _, root := range roots {
		if _, err := filepath.Abs(root); err != nil {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if !d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if rel != "" && rel != "." {
				dirs[rel+"/"] = true
			}
			return nil
		})
	}

	seen := map[string]bool{}
	for _, sig := range sdkSignatures {
		for _, prefix := range sig.Prefixes {
			matched := false
			for d := range dirs {
				if strings.HasPrefix(d, prefix) {
					matched = true
					if !seen[sig.Name] {
						res.SDKs = append(res.SDKs, SDK{Name: sig.Name, Category: sig.Category, Match: prefix})
						seen[sig.Name] = true
					}
					break
				}
			}
			if matched {
				break
			}
		}
	}
	return res, nil
}
