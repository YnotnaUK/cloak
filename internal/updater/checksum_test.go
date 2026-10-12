package updater

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseChecksum(t *testing.T) {
	const binaryName = "cloak-linux-amd64"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte("binary")))
	for _, tc := range []struct {
		name, manifest string
		ok             bool
	}{
		{"text mode", digest + "  " + binaryName + "\n", true},
		{"binary mode", digest + " *" + binaryName + "\n", true},
		{"upper case", strings.ToUpper(digest) + "  " + binaryName + "\n", true},
		{"multiple platforms", digest + "  cloak-darwin-arm64\n" + digest + "  " + binaryName + "\n", true},
		{"empty manifest", "", false},
		{"missing binary", digest + "  cloak-linux-arm64\n", false},
		{"duplicate binary", strings.Repeat(digest+"  "+binaryName+"\n", 2), false},
		{"short checksum", "abc  " + binaryName + "\n", false},
		{"invalid hex", strings.Repeat("g", 64) + "  " + binaryName + "\n", false},
		{"extra fields", digest + "  " + binaryName + " extra\n", false},
		{"malformed other entry", digest + "  " + binaryName + "\ninvalid\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := releaseChecksum(tc.manifest, binaryName)
			if (err == nil) != tc.ok {
				t.Fatalf("releaseChecksum error = %v", err)
			}
			if tc.ok && got != digest {
				t.Fatalf("checksum = %q, want %q", got, digest)
			}
		})
	}
}

func TestDownloadVerifiedBinary(t *testing.T) {
	const binaryName = "cloak-linux-amd64"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte("new binary")))
	for _, tc := range []struct {
		name           string
		manifest       string
		manifestStatus int
		binary         string
		binaryStatus   int
		interrupted    bool
		ok             bool
	}{
		{"verified", digest + "  " + binaryName + "\n", 200, "new binary", 200, false, true},
		{"missing manifest", "", 404, "new binary", 200, false, false},
		{"manifest HTTP error", "", 500, "new binary", 200, false, false},
		{"missing entry", digest + "  cloak-linux-arm64\n", 200, "new binary", 200, false, false},
		{"duplicate entry", strings.Repeat(digest+"  "+binaryName+"\n", 2), 200, "new binary", 200, false, false},
		{"malformed manifest", "invalid", 200, "new binary", 200, false, false},
		{"oversized manifest", strings.Repeat("a", 1024*1024+1), 200, "new binary", 200, false, false},
		{"binary HTTP error", digest + "  " + binaryName + "\n", 200, "", 404, false, false},
		{"tampered binary", digest + "  " + binaryName + "\n", 200, "tampered binary", 200, false, false},
		{"empty binary", digest + "  " + binaryName + "\n", 200, "", 200, false, false},
		{"interrupted binary", digest + "  " + binaryName + "\n", 200, "partial", 200, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "cloak")
			if err := os.WriteFile(path, []byte("old binary"), 0755); err != nil {
				t.Fatal(err)
			}
			var requests []string
			mockHTTP(t, func(r *http.Request) (*http.Response, error) {
				requests = append(requests, r.URL.Path)
				if strings.HasSuffix(r.URL.Path, "/SHA256SUMS") {
					return response(tc.manifest, tc.manifestStatus), nil
				}
				resp := response(tc.binary, tc.binaryStatus)
				if tc.interrupted {
					resp.Body = io.NopCloser(io.MultiReader(strings.NewReader(tc.binary), failingReader{}))
				}
				return resp, nil
			})
			err := downloadVerifiedBinary(context.Background(), path,
				"https://github.com/ynotnauk/cloak/releases/download/v0.2.0", binaryName)
			if (err == nil) != tc.ok {
				t.Fatalf("downloadVerifiedBinary error = %v", err)
			}
			if len(requests) == 0 || !strings.HasSuffix(requests[0], "/SHA256SUMS") {
				t.Fatalf("manifest not fetched first: %v", requests)
			}
			want := "old binary"
			if tc.ok {
				want = "new binary"
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != want {
				t.Fatalf("installed binary = %q, %v; want %q", data, err, want)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0755 {
				t.Fatalf("installed file mode incorrect: %v, %v", info, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("temporary files not cleaned up: %v, %v", entries, err)
			}
		})
	}
}
