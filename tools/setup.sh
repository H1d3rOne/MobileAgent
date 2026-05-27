#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
TMP_DIR="$SCRIPT_DIR/.tmp"

# Tool versions
ADB_VERSION="35.0.2"
APKTOOL_VERSION="2.10.0"
JADX_VERSION="1.5.1"
DEX2JAR_VERSION="2.4"
FRIDA_VERSION="16.6.6"
RADARE2_VERSION="6.1.4"
UBER_APK_SIGNER_VERSION="1.3.0"
BUNDLETOOL_VERSION="1.18.3"

# Detect platform
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  darwin) PLATFORM="darwin" ;;
  linux)  PLATFORM="linux" ;;
  *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH="x86_64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)             echo "Unsupported arch: $ARCH"; exit 1 ;;
esac

echo "Platform: $PLATFORM/$ARCH"
echo "Install dir: $BIN_DIR"
echo ""

mkdir -p "$BIN_DIR" "$TMP_DIR"

# =========================================================================
# Helper functions
# =========================================================================

download() {
  local url="$1" dest="$2"
  echo "  Downloading: $url"
  curl -fSL --progress-bar -o "$dest" "$url"
}

check_java() {
  if ! command -v java &>/dev/null; then
    echo "WARNING: Java not found. apktool/jadx/d2j-dex2jar require Java 11+."
    echo "  Install via: brew install openjdk@17 (macOS) or apt install openjdk-17-jdk (Linux)"
  fi
}

# =========================================================================
# ADB (Android Platform Tools)
# =========================================================================

install_adb() {
  if [ -f "$BIN_DIR/adb" ]; then
    echo "[adb] Already installed, skipping. Delete $BIN_DIR/adb to reinstall."
    return
  fi
  echo "[adb] Installing Android Platform Tools..."
  local url
  case "$PLATFORM" in
    darwin) url="https://dl.google.com/android/repository/platform-tools-latest-${PLATFORM}.zip" ;;
    linux)  url="https://dl.google.com/android/repository/platform-tools-latest-${PLATFORM}.zip" ;;
  esac
  download "$url" "$TMP_DIR/platform-tools.zip"
  unzip -qo "$TMP_DIR/platform-tools.zip" -d "$TMP_DIR/"
  cp "$TMP_DIR/platform-tools/adb" "$BIN_DIR/adb"
  cp "$TMP_DIR/platform-tools/fastboot" "$BIN_DIR/fastboot"
  chmod +x "$BIN_DIR/adb" "$BIN_DIR/fastboot"
  rm -rf "$TMP_DIR/platform-tools" "$TMP_DIR/platform-tools.zip"
  echo "[adb] Done: $("$BIN_DIR/adb" --version | head -1)"
}

# =========================================================================
# apktool
# =========================================================================

install_apktool() {
  if [ -f "$BIN_DIR/apktool.jar" ]; then
    echo "[apktool] Already installed, skipping."
    return
  fi
  echo "[apktool] Installing v${APKTOOL_VERSION}..."
  download "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
    "$BIN_DIR/apktool.jar"

  cat > "$BIN_DIR/apktool" <<'WRAPPER'
#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec java -jar "$DIR/apktool.jar" "$@"
WRAPPER
  chmod +x "$BIN_DIR/apktool"
  echo "[apktool] Done."
}

# =========================================================================
# jadx
# =========================================================================

install_jadx() {
  if [ -f "$BIN_DIR/jadx" ]; then
    echo "[jadx] Already installed, skipping."
    return
  fi
  echo "[jadx] Installing v${JADX_VERSION}..."
  download "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
    "$TMP_DIR/jadx.zip"
  unzip -qo "$TMP_DIR/jadx.zip" -d "$TMP_DIR/jadx"
  cp -r "$TMP_DIR/jadx/lib" "$BIN_DIR/jadx-lib"
  cp "$TMP_DIR/jadx/bin/jadx" "$BIN_DIR/jadx"
  cp "$TMP_DIR/jadx/bin/jadx-gui" "$BIN_DIR/jadx-gui"
  chmod +x "$BIN_DIR/jadx" "$BIN_DIR/jadx-gui"
  # Fix jadx script to use relative lib path
  sed -i.bak 's|APP_HOME=.*|APP_HOME="$(cd "$(dirname "$0")" \&\& pwd)"|' "$BIN_DIR/jadx" 2>/dev/null || true
  sed -i.bak 's|$APP_HOME/lib|$APP_HOME/jadx-lib|g' "$BIN_DIR/jadx" 2>/dev/null || true
  rm -f "$BIN_DIR/jadx.bak"
  rm -rf "$TMP_DIR/jadx" "$TMP_DIR/jadx.zip"
  echo "[jadx] Done."
}

# =========================================================================
# dex2jar
# =========================================================================

install_dex2jar() {
  if [ -f "$BIN_DIR/d2j-dex2jar" ] || [ -f "$BIN_DIR/d2j-dex2jar.sh" ]; then
    echo "[dex2jar] Already installed, skipping."
    return
  fi
  echo "[dex2jar] Installing v${DEX2JAR_VERSION}..."
  download "https://github.com/pxb1988/dex2jar/releases/download/v${DEX2JAR_VERSION}/dex-tools-v${DEX2JAR_VERSION}.zip" \
    "$TMP_DIR/dex2jar.zip"
  unzip -qo "$TMP_DIR/dex2jar.zip" -d "$TMP_DIR/"
  local extracted_dir
  extracted_dir=$(find "$TMP_DIR" -maxdepth 1 -type d -name "dex-tools*" | head -1)
  if [ -z "$extracted_dir" ]; then
    echo "[dex2jar] ERROR: Could not find extracted directory"
    return
  fi
  cp -r "$extracted_dir/lib" "$BIN_DIR/d2j-lib"
  cp "$extracted_dir"/*.sh "$BIN_DIR/" 2>/dev/null || true
  cp "$extracted_dir"/*.bat "$BIN_DIR/" 2>/dev/null || true
  chmod +x "$BIN_DIR"/d2j-*.sh 2>/dev/null || true
  # Create convenience symlink without .sh extension
  ln -sf "d2j-dex2jar.sh" "$BIN_DIR/d2j-dex2jar" 2>/dev/null || true
  rm -rf "$extracted_dir" "$TMP_DIR/dex2jar.zip"
  echo "[dex2jar] Done."
}

# =========================================================================
# Frida
# =========================================================================

install_frida() {
  if [ -f "$BIN_DIR/frida" ]; then
    echo "[frida] Already installed, skipping."
    return
  fi
  echo "[frida] Installing v${FRIDA_VERSION} (pip)..."

  # Create a local venv for frida to avoid polluting system python
  local venv_dir="$SCRIPT_DIR/.venv"
  if [ ! -d "$venv_dir" ]; then
    python3 -m venv "$venv_dir"
  fi
  "$venv_dir/bin/pip" install -q "frida-tools==${FRIDA_VERSION}" 2>/dev/null || \
    "$venv_dir/bin/pip" install -q frida-tools

  # Symlink frida binaries into bin/
  for cmd in frida frida-ps frida-trace frida-discover frida-kill frida-ls-devices; do
    if [ -f "$venv_dir/bin/$cmd" ]; then
      ln -sf "$venv_dir/bin/$cmd" "$BIN_DIR/$cmd"
    fi
  done
  echo "[frida] Done: $("$BIN_DIR/frida" --version 2>/dev/null || echo 'installed')"
}

# =========================================================================
# Frida Server (for pushing to device)
# =========================================================================

install_frida_server() {
  local frida_ver
  frida_ver=$("$BIN_DIR/frida" --version 2>/dev/null || echo "$FRIDA_VERSION")
  local server_file="$BIN_DIR/frida-server-android-arm64"

  if [ -f "$server_file" ]; then
    echo "[frida-server] Already downloaded, skipping."
    return
  fi
  echo "[frida-server] Downloading for Android arm64 (v${frida_ver})..."
  local url="https://github.com/frida/frida/releases/download/${frida_ver}/frida-server-${frida_ver}-android-arm64.xz"
  download "$url" "$TMP_DIR/frida-server.xz"
  xz -d "$TMP_DIR/frida-server.xz"
  mv "$TMP_DIR/frida-server" "$server_file"
  chmod +x "$server_file"
  echo "[frida-server] Done. Push to device with:"
  echo "  adb push $server_file /data/local/tmp/frida-server"
  echo "  adb shell 'chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &'"
}

# =========================================================================
# Build tools (aapt2, zipalign, apksigner)
# =========================================================================

install_build_tools() {
  if [ -f "$BIN_DIR/aapt2" ]; then
    echo "[build-tools] Already installed, skipping."
    return
  fi
  echo "[build-tools] Installing aapt2, zipalign, apksigner..."
  # Google provides build-tools as part of cmdline-tools; we download the standalone package
  local bt_version="35.0.0"
  local url
  case "$PLATFORM" in
    darwin) url="https://dl.google.com/android/repository/build-tools_r${bt_version}-macosx.zip" ;;
    linux)  url="https://dl.google.com/android/repository/build-tools_r${bt_version}-linux.zip" ;;
  esac
  download "$url" "$TMP_DIR/build-tools.zip" 2>/dev/null || {
    echo "[build-tools] Download failed. You can install manually via Android SDK Manager."
    return
  }
  unzip -qo "$TMP_DIR/build-tools.zip" -d "$TMP_DIR/build-tools-extracted"
  local bt_dir
  bt_dir=$(find "$TMP_DIR/build-tools-extracted" -maxdepth 1 -type d | tail -1)
  for tool in aapt aapt2 zipalign apksigner; do
    if [ -f "$bt_dir/$tool" ]; then
      cp "$bt_dir/$tool" "$BIN_DIR/$tool"
      chmod +x "$BIN_DIR/$tool"
    fi
  done
  # apksigner is a jar with a wrapper
  if [ -f "$bt_dir/lib/apksigner.jar" ]; then
    mkdir -p "$BIN_DIR/lib"
    cp "$bt_dir/lib/apksigner.jar" "$BIN_DIR/lib/"
  fi
  rm -rf "$TMP_DIR/build-tools-extracted" "$TMP_DIR/build-tools.zip"
  echo "[build-tools] Done."
}

# =========================================================================
# objection (Frida-based runtime exploration)
# =========================================================================

install_objection() {
  if [ -f "$BIN_DIR/objection" ]; then
    echo "[objection] Already installed, skipping."
    return
  fi
  echo "[objection] Installing..."
  local venv_dir="$SCRIPT_DIR/.venv"
  if [ ! -d "$venv_dir" ]; then
    python3 -m venv "$venv_dir"
  fi
  "$venv_dir/bin/pip" install -q objection
  ln -sf "$venv_dir/bin/objection" "$BIN_DIR/objection"
  echo "[objection] Done."
}

# =========================================================================
# androguard (Python APK analysis library)
# =========================================================================

install_androguard() {
  if [ -f "$BIN_DIR/androguard" ]; then
    echo "[androguard] Already installed, skipping."
    return
  fi
  echo "[androguard] Installing..."
  local venv_dir="$SCRIPT_DIR/.venv"
  if [ ! -d "$venv_dir" ]; then
    python3 -m venv "$venv_dir"
  fi
  "$venv_dir/bin/pip" install -q androguard
  for cmd in androguard androaxml androarsc androcg androdis androlyze; do
    if [ -f "$venv_dir/bin/$cmd" ]; then
      ln -sf "$venv_dir/bin/$cmd" "$BIN_DIR/$cmd"
    fi
  done
  echo "[androguard] Done."
}

# =========================================================================
# radare2 (binary analysis framework)
# =========================================================================

install_radare2() {
  if [ -f "$BIN_DIR/r2" ]; then
    echo "[radare2] Already installed, skipping."
    return
  fi
  echo "[radare2] Installing v${RADARE2_VERSION}..."
  local url
  case "${PLATFORM}_${ARCH}" in
    darwin_arm64)
      url="https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2-arm64-${RADARE2_VERSION}.pkg"
      download "$url" "$TMP_DIR/radare2.pkg"
      pkgutil --expand-full "$TMP_DIR/radare2.pkg" "$TMP_DIR/radare2-pkg"
      local r2_src="$TMP_DIR/radare2-pkg/Payload/usr/local"
      if [ -d "$r2_src/bin" ]; then
        for cmd in r2 rabin2 rasm2 rahash2 rafind2 radiff2 radare2; do
          if [ -f "$r2_src/bin/$cmd" ]; then
            cp "$r2_src/bin/$cmd" "$BIN_DIR/$cmd"
            chmod +x "$BIN_DIR/$cmd"
          fi
        done
      fi
      if [ -d "$r2_src/lib" ]; then
        cp -r "$r2_src/lib" "$BIN_DIR/r2-lib"
      fi
      rm -rf "$TMP_DIR/radare2-pkg" "$TMP_DIR/radare2.pkg"
      ;;
    darwin_x86_64)
      url="https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2-x64-${RADARE2_VERSION}.pkg"
      download "$url" "$TMP_DIR/radare2.pkg"
      pkgutil --expand-full "$TMP_DIR/radare2.pkg" "$TMP_DIR/radare2-pkg"
      local r2_src="$TMP_DIR/radare2-pkg/Payload/usr/local"
      if [ -d "$r2_src/bin" ]; then
        for cmd in r2 rabin2 rasm2 rahash2 rafind2 radiff2 radare2; do
          if [ -f "$r2_src/bin/$cmd" ]; then
            cp "$r2_src/bin/$cmd" "$BIN_DIR/$cmd"
            chmod +x "$BIN_DIR/$cmd"
          fi
        done
      fi
      rm -rf "$TMP_DIR/radare2-pkg" "$TMP_DIR/radare2.pkg"
      ;;
    linux_amd64|linux_x86_64)
      url="https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2_${RADARE2_VERSION}_amd64.deb"
      download "$url" "$TMP_DIR/radare2.deb"
      mkdir -p "$TMP_DIR/radare2-deb"
      ar x "$TMP_DIR/radare2.deb" --output="$TMP_DIR/radare2-deb" 2>/dev/null || \
        (cd "$TMP_DIR/radare2-deb" && ar x "$TMP_DIR/radare2.deb")
      tar -xf "$TMP_DIR/radare2-deb"/data.tar* -C "$TMP_DIR/radare2-deb/"
      for cmd in r2 rabin2 rasm2 rahash2 rafind2 radiff2; do
        local found
        found=$(find "$TMP_DIR/radare2-deb" -type f -name "$cmd" | head -1)
        if [ -n "$found" ]; then
          cp "$found" "$BIN_DIR/$cmd"
          chmod +x "$BIN_DIR/$cmd"
        fi
      done
      rm -rf "$TMP_DIR/radare2-deb" "$TMP_DIR/radare2.deb"
      ;;
    linux_arm64)
      url="https://github.com/radareorg/radare2/releases/download/${RADARE2_VERSION}/radare2_${RADARE2_VERSION}_arm64.deb"
      download "$url" "$TMP_DIR/radare2.deb"
      mkdir -p "$TMP_DIR/radare2-deb"
      ar x "$TMP_DIR/radare2.deb" --output="$TMP_DIR/radare2-deb" 2>/dev/null || \
        (cd "$TMP_DIR/radare2-deb" && ar x "$TMP_DIR/radare2.deb")
      tar -xf "$TMP_DIR/radare2-deb"/data.tar* -C "$TMP_DIR/radare2-deb/"
      for cmd in r2 rabin2 rasm2 rahash2 rafind2 radiff2; do
        local found
        found=$(find "$TMP_DIR/radare2-deb" -type f -name "$cmd" | head -1)
        if [ -n "$found" ]; then
          cp "$found" "$BIN_DIR/$cmd"
          chmod +x "$BIN_DIR/$cmd"
        fi
      done
      rm -rf "$TMP_DIR/radare2-deb" "$TMP_DIR/radare2.deb"
      ;;
  esac
  if [ -f "$BIN_DIR/r2" ]; then
    echo "[radare2] Done: $("$BIN_DIR/r2" -v 2>/dev/null | head -1 || echo 'installed')"
  else
    echo "[radare2] WARNING: Installation may have failed. Try: brew install radare2"
  fi
}

# =========================================================================
# uber-apk-signer (simplified APK signing)
# =========================================================================

install_uber_apk_signer() {
  if [ -f "$BIN_DIR/uber-apk-signer.jar" ]; then
    echo "[uber-apk-signer] Already installed, skipping."
    return
  fi
  echo "[uber-apk-signer] Installing v${UBER_APK_SIGNER_VERSION}..."
  download "https://github.com/patrickfav/uber-apk-signer/releases/download/v${UBER_APK_SIGNER_VERSION}/uber-apk-signer-${UBER_APK_SIGNER_VERSION}.jar" \
    "$BIN_DIR/uber-apk-signer.jar"

  cat > "$BIN_DIR/uber-apk-signer" <<'WRAPPER'
#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec java -jar "$DIR/uber-apk-signer.jar" "$@"
WRAPPER
  chmod +x "$BIN_DIR/uber-apk-signer"
  echo "[uber-apk-signer] Done."
}

# =========================================================================
# bundletool (AAB processing)
# =========================================================================

install_bundletool() {
  if [ -f "$BIN_DIR/bundletool.jar" ]; then
    echo "[bundletool] Already installed, skipping."
    return
  fi
  echo "[bundletool] Installing v${BUNDLETOOL_VERSION}..."
  download "https://github.com/google/bundletool/releases/download/${BUNDLETOOL_VERSION}/bundletool-all-${BUNDLETOOL_VERSION}.jar" \
    "$BIN_DIR/bundletool.jar"

  cat > "$BIN_DIR/bundletool" <<'WRAPPER'
#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec java -jar "$DIR/bundletool.jar" "$@"
WRAPPER
  chmod +x "$BIN_DIR/bundletool"
  echo "[bundletool] Done."
}

# =========================================================================
# mitmproxy (HTTPS interception proxy)
# =========================================================================

install_mitmproxy() {
  if [ -f "$BIN_DIR/mitmproxy" ]; then
    echo "[mitmproxy] Already installed, skipping."
    return
  fi
  echo "[mitmproxy] Installing..."
  local venv_dir="$SCRIPT_DIR/.venv"
  if [ ! -d "$venv_dir" ]; then
    python3 -m venv "$venv_dir"
  fi
  "$venv_dir/bin/pip" install -q mitmproxy
  for cmd in mitmproxy mitmdump mitmweb; do
    if [ -f "$venv_dir/bin/$cmd" ]; then
      ln -sf "$venv_dir/bin/$cmd" "$BIN_DIR/$cmd"
    fi
  done
  echo "[mitmproxy] Done."
}

# =========================================================================
# Main
# =========================================================================

echo "============================================"
echo " MobileAgent Tools Setup"
echo "============================================"
echo ""

check_java

install_adb
install_apktool
install_jadx
install_dex2jar
install_frida
install_frida_server
install_build_tools
install_objection
install_androguard
install_radare2
install_uber_apk_signer
install_bundletool
install_mitmproxy

# Clean up tmp
rm -rf "$TMP_DIR"

echo ""
echo "============================================"
echo " Setup complete!"
echo "============================================"
echo ""
echo "All tools installed to: $BIN_DIR"
echo ""
echo "Installed tools:"
echo "  - adb, fastboot        (device communication)"
echo "  - apktool              (smali decompile/recompile)"
echo "  - jadx                 (DEX → Java source)"
echo "  - dex2jar              (DEX → JAR)"
echo "  - frida, objection     (dynamic instrumentation)"
echo "  - radare2 (r2)         (native binary analysis)"
echo "  - androguard           (Python APK analysis)"
echo "  - uber-apk-signer      (simplified signing)"
echo "  - bundletool           (AAB processing)"
echo "  - mitmproxy            (HTTPS interception)"
echo "  - build-tools          (aapt2, zipalign, apksigner)"
echo ""
echo "Add to your PATH (optional):"
echo "  export PATH=\"$BIN_DIR:\$PATH\""
echo ""
