package analyzer

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

func ParseCertificate(apkPath string) (*CertificateResult, error) {
	if cert, err := parseWithApksigner(apkPath); err == nil {
		return cert, nil
	}
	return parseWithKeytool(apkPath)
}

var (
	reSig    = regexp.MustCompile(`(?m)^Signer #\d+ certificate (?:SHA-?256|SHA256) digest:\s*([0-9a-fA-F:]+)`)
	reSig1   = regexp.MustCompile(`(?m)^Signer #\d+ certificate SHA-?1 digest:\s*([0-9a-fA-F:]+)`)
	reSubj   = regexp.MustCompile(`(?m)^Signer #\d+ certificate DN:\s*(.+)$`)
	reV1     = regexp.MustCompile(`(?m)^Verified using v1 scheme \(JAR signing\):\s*(true|false)`)
	reV2     = regexp.MustCompile(`(?m)^Verified using v2 scheme \(APK Signature Scheme v2\):\s*(true|false)`)
	reV3     = regexp.MustCompile(`(?m)^Verified using v3 scheme \(APK Signature Scheme v3\):\s*(true|false)`)
)

func parseWithApksigner(apkPath string) (*CertificateResult, error) {
	out, err := exec.Command("apksigner", "verify", "--print-certs", "-v", apkPath).CombinedOutput()
	text := string(out)
	if err != nil && !strings.Contains(text, "Signer #") {
		return nil, fmt.Errorf("apksigner: %w\n%s", err, text)
	}
	res := &CertificateResult{Tool: "apksigner", Raw: text}
	if m := reSig.FindStringSubmatch(text); len(m) > 1 {
		res.SHA256 = strings.ToUpper(strings.ReplaceAll(m[1], ":", ""))
	}
	if m := reSig1.FindStringSubmatch(text); len(m) > 1 {
		res.SHA1 = strings.ToUpper(strings.ReplaceAll(m[1], ":", ""))
	}
	if m := reSubj.FindStringSubmatch(text); len(m) > 1 {
		res.Subject = strings.TrimSpace(m[1])
	}
	if m := reV1.FindStringSubmatch(text); len(m) > 1 {
		res.V1Verified = m[1] == "true"
	}
	if m := reV2.FindStringSubmatch(text); len(m) > 1 {
		res.V2Verified = m[1] == "true"
	}
	if m := reV3.FindStringSubmatch(text); len(m) > 1 {
		res.V3Verified = m[1] == "true"
	}
	res.Debug = strings.Contains(strings.ToLower(res.Subject), "android debug") ||
		strings.Contains(strings.ToLower(res.Subject), "androiddebugkey")
	return res, nil
}

func parseWithKeytool(apkPath string) (*CertificateResult, error) {
	pemBytes, err := extractCertPEM(apkPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("decode pem failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	sum1 := sha1.Sum(cert.Raw)
	sum256 := sha256.Sum256(cert.Raw)
	subj := cert.Subject.String()
	return &CertificateResult{
		Tool:      "x509",
		SHA1:      strings.ToUpper(hex.EncodeToString(sum1[:])),
		SHA256:    strings.ToUpper(hex.EncodeToString(sum256[:])),
		Subject:   subj,
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore.UTC(),
		NotAfter:  cert.NotAfter.UTC(),
		SerialHex: cert.SerialNumber.Text(16),
		Algorithm: cert.SignatureAlgorithm.String(),
		Debug:     strings.Contains(strings.ToLower(subj), "android debug"),
	}, nil
}

func extractCertPEM(apkPath string) ([]byte, error) {
	out, err := exec.Command("keytool", "-printcert", "-jarfile", apkPath, "-rfc").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("keytool: %w\n%s", err, string(out))
	}
	if i := strings.Index(string(out), "-----BEGIN"); i >= 0 {
		return out[i:], nil
	}
	return nil, fmt.Errorf("no PEM block in keytool output")
}

