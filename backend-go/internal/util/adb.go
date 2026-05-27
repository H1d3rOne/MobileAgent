package util

import (
	"fmt"
	"os/exec"
	"strings"
)

func RunADB(adbPath string, args ...string) (string, error) {
	cmd := exec.Command(adbPath, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func ParseDevices(raw string) []map[string]string {
	var devices []map[string]string
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "List of devices") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			devices = append(devices, map[string]string{
				"serial": parts[0],
				"status": parts[1],
			})
		}
	}
	return devices
}

func GetDeviceProp(adbPath, serial, prop string) (string, error) {
	return RunADB(adbPath, "-s", serial, "shell", "getprop", prop)
}

func ConnectDevice(adbPath, addr string) (string, error) {
	return RunADB(adbPath, "connect", addr)
}

func DisconnectDevice(adbPath, addr string) (string, error) {
	return RunADB(adbPath, "disconnect", addr)
}

func ShellCommand(adbPath, serial, cmd string) (string, error) {
	return RunADB(adbPath, "-s", serial, "shell", cmd)
}

func Screenshot(adbPath, serial, remotePath string) (string, error) {
	out, err := RunADB(adbPath, "-s", serial, "shell", "screencap", "-p", remotePath)
	if err != nil {
		return out, err
	}
	return out, nil
}

func PullFile(adbPath, serial, remotePath, localPath string) (string, error) {
	return RunADB(adbPath, "-s", serial, "pull", remotePath, localPath)
}

func InstallAPK(adbPath, serial, apkPath string) (string, error) {
	return RunADB(adbPath, "-s", serial, "install", "-r", apkPath)
}

func UninstallApp(adbPath, serial, pkg string) (string, error) {
	return RunADB(adbPath, "-s", serial, "uninstall", pkg)
}

func ListPackages(adbPath, serial string) (string, error) {
	return RunADB(adbPath, "-s", serial, "shell", "pm", "list", "packages", "-3")
}

func DumpUI(adbPath, serial string) (string, error) {
	out, err := RunADB(adbPath, "-s", serial, "shell", "uiautomator", "dump", "/sdcard/window_dump.xml")
	if err != nil {
		return "", fmt.Errorf("uiautomator dump: %w", err)
	}
	_ = out
	return RunADB(adbPath, "-s", serial, "shell", "cat", "/sdcard/window_dump.xml")
}
