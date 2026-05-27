package runner

import (
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/mobileagent/backend-go/internal/config"
	"github.com/mobileagent/backend-go/internal/model"
	"github.com/mobileagent/backend-go/internal/util"
)

type ADBRunner struct {
	cfg *config.Config
}

func NewADBRunner(cfg *config.Config) *ADBRunner {
	return &ADBRunner{cfg: cfg}
}

func (r *ADBRunner) ListDevices() ([]map[string]string, error) {
	out, err := util.RunADB(r.cfg.ADB.Path, "devices")
	if err != nil {
		return nil, fmt.Errorf("adb devices: %w", err)
	}
	return util.ParseDevices(out), nil
}

func (r *ADBRunner) ConnectDevice(addr string) error {
	out, err := util.ConnectDevice(r.cfg.ADB.Path, addr)
	if err != nil {
		return fmt.Errorf("connect %s: %w (output: %s)", addr, err, out)
	}
	zap.L().Info("Device connected", zap.String("addr", addr))
	return nil
}

func (r *ADBRunner) DisconnectDevice(addr string) error {
	_, err := util.DisconnectDevice(r.cfg.ADB.Path, addr)
	return err
}

func (r *ADBRunner) RefreshDeviceInfo(d *model.Device) error {
	props := map[string]string{
		"model":       "ro.product.model",
		"brand":       "ro.product.brand",
		"android_ver": "ro.build.version.release",
		"sdk_version": "ro.build.version.sdk",
	}
	for k, prop := range props {
		val, err := util.GetDeviceProp(r.cfg.ADB.Path, d.Serial, prop)
		if err != nil {
			zap.L().Warn("get prop failed", zap.String("prop", prop), zap.Error(err))
			continue
		}
		switch k {
		case "model":
			d.Model = val
		case "brand":
			d.Brand = val
		case "android_ver":
			d.AndroidVersion = val
		case "sdk_version":
			// parse int
			var sdk int
			fmt.Sscanf(val, "%d", &sdk)
			d.SDKVersion = sdk
		}
	}
	return nil
}

func (r *ADBRunner) Shell(serial, cmd string) (string, error) {
	return util.ShellCommand(r.cfg.ADB.Path, serial, cmd)
}

func (r *ADBRunner) Screenshot(serial string) (string, error) {
	remotePath := "/sdcard/screenshot.png"
	localPath := fmt.Sprintf("/tmp/ma_screenshot_%s.png", serial)
	_, err := util.Screenshot(r.cfg.ADB.Path, serial, remotePath)
	if err != nil {
		return "", err
	}
	_, err = util.PullFile(r.cfg.ADB.Path, serial, remotePath, localPath)
	if err != nil {
		return "", err
	}
	return localPath, nil
}

func (r *ADBRunner) DumpUI(serial string) (string, error) {
	return util.DumpUI(r.cfg.ADB.Path, serial)
}

func (r *ADBRunner) AutoConnect() {
	if !r.cfg.ADB.AutoConnect {
		return
	}
	for _, addr := range r.cfg.ADB.AutoConnectAddrs {
		if err := r.ConnectDevice(addr); err != nil {
			zap.L().Warn("auto connect failed", zap.String("addr", addr), zap.Error(err))
		}
	}
}

func (r *ADBRunner) StartLogcat(serial, outputPath string) error {
	zap.L().Info("logcat would be started", zap.String("serial", serial))
	return nil
}

func (r *ADBRunner) WaitForDevice(serial string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		devices, err := r.ListDevices()
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		for _, d := range devices {
			if d["serial"] == serial && d["status"] == "device" {
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("device %s not available after %v", serial, timeout)
}
