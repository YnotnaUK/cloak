package cloak_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestInstallerChecksumVerification(t *testing.T) {
	script, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	const binary = "#!/usr/bin/env bash\necho 'test version'\n"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(binary)))
	for _, channel := range []string{"stable", "preview"} {
		for _, tool := range []string{"sha256sum", "shasum"} {
			for _, installation := range []string{"direct", "sudo"} {
				for _, tc := range []struct {
					name, manifest, body string
					failManifest         bool
					failBinary           bool
					ok                   bool
				}{
					{"verified", digest + "  BINARY\n", binary, false, false, true},
					{"tampered", digest + "  BINARY\n", binary + "# tampered\n", false, false, false},
					{"missing manifest", "", binary, true, false, false},
					{"missing entry", digest + "  cloak-windows-amd64.exe\n", binary, false, false, false},
					{"duplicate entry", strings.Repeat(digest+"  BINARY\n", 2), binary, false, false, false},
					{"invalid manifest", strings.Repeat("g", 64) + "  BINARY\n", binary, false, false, false},
					{"empty manifest", "", binary, false, false, false},
					{"empty binary", digest + "  BINARY\n", "", false, false, false},
					{"failed download", digest + "  BINARY\n", binary, false, true, false},
					{"failed install", digest + "  BINARY\n", binary, false, false, false},
				} {
					t.Run(channel+"/"+tool+"/"+installation+"/"+tc.name, func(t *testing.T) {
						if _, err := exec.LookPath(tool); err != nil {
							t.Skipf("requires %s", tool)
						}
						if channel == "preview" {
							if _, err := exec.LookPath("jq"); err != nil {
								t.Skip("preview test requires jq")
							}
						}
						dir := t.TempDir()
						installDir := filepath.Join(dir, "install")
						tempDir := filepath.Join(dir, "downloads")
						for _, path := range []string{installDir, tempDir} {
							if err := os.Mkdir(path, 0755); err != nil {
								t.Fatal(err)
							}
						}
						execPath := filepath.Join(installDir, "cloak")
						if err := os.WriteFile(execPath, []byte("old binary"), 0755); err != nil {
							t.Fatal(err)
						}
						binaryName := "cloak-linux-amd64"
						osName := "Linux"
						if tool == "shasum" {
							binaryName = "cloak-darwin-amd64"
							osName = "Darwin"
						}
						for name, data := range map[string]string{
							"manifest": strings.ReplaceAll(tc.manifest, "BINARY", binaryName),
							"binary":   tc.body,
						} {
							if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
								t.Fatal(err)
							}
						}
						mock := `
umask 077
[() {
  if [[ "$1" == -w && "$INSTALLATION" == sudo ]]; then
    return 1
  fi
  builtin [ "$@"
}
sudo() {
  printf '%s\n' "$*" > "$TEST_DIR/sudo-command"
  "$@"
}
install() {
  if [[ "$FAIL_INSTALL" == true ]]; then return 1; fi
  builtin command install "$@"
}
command() {
  if [[ "$*" == "-v sha256sum" && "$CHECKSUM_TOOL_TEST" == shasum ]]; then
    return 1
  fi
  builtin command "$@"
}
uname() {
  if [[ "$1" == -s ]]; then echo "$TEST_OS"; else echo x86_64; fi
}
curl() {
  case "$*" in
    *"/releases/latest")
      printf 'https://github.com/ynotnauk/cloak/releases/tag/v0.2.0'
      ;;
    *"page=1")
      echo '[{"tag_name":"v0.2.0-preview.20261012100000","prerelease":true,"draft":false}]'
      ;;
    *"page=2") echo '[]' ;;
    *"/SHA256SUMS"*)
      if [[ "$FAIL_MANIFEST" == true ]]; then return 22; fi
      cat "$TEST_DIR/manifest" > "$4"
      ;;
    *"/download/"*)
      if [[ "$FAIL_BINARY" == true ]]; then return 22; fi
      cat "$TEST_DIR/binary" > "$4"
      ;;
    *) return 99 ;;
  esac
}
`
						localScript := strings.Replace(string(script), `INSTALL_DIR="/usr/local/bin"`, `INSTALL_DIR="`+installDir+`"`, 1)
						args := []string{"-c", mock + localScript, "install.sh"}
						if channel == "preview" {
							args = append(args, "--preview", "0.2")
						}
						cmd := exec.Command("bash", args...)
						cmd.Env = append(os.Environ(), "TEST_DIR="+dir, "TMPDIR="+tempDir,
							"CHECKSUM_TOOL_TEST="+tool, "TEST_OS="+osName,
							"INSTALLATION="+installation,
							fmt.Sprintf("FAIL_INSTALL=%t", tc.name == "failed install"),
							fmt.Sprintf("FAIL_MANIFEST=%t", tc.failManifest),
							fmt.Sprintf("FAIL_BINARY=%t", tc.failBinary))
						out, err := cmd.CombinedOutput()
						if (err == nil) != tc.ok {
							t.Fatalf("installer error = %v\n%s", err, out)
						}
						want := "old binary"
						if tc.ok {
							want = binary
						}
						data, err := os.ReadFile(execPath)
						if err != nil || string(data) != want {
							t.Fatalf("installed binary = %q, %v; want %q", data, err, want)
						}
						info, err := os.Stat(execPath)
						if err != nil {
							t.Fatal(err)
						}
						if info.Mode().Perm() != 0755 {
							t.Fatalf("installed mode = %v, want 0755", info.Mode().Perm())
						}
						if tc.ok && installation == "sudo" {
							command, err := os.ReadFile(filepath.Join(dir, "sudo-command"))
							if err != nil || !strings.HasPrefix(string(command), "install -m 0755 ") {
								t.Fatalf("sudo installation command = %q, %v", command, err)
							}
						}
						if !tc.ok && strings.Contains(string(out), "Successfully installed") {
							t.Fatalf("installer reported success after failure: %s", out)
						}
						leftover, err := os.ReadDir(tempDir)
						if err != nil || len(leftover) != 0 {
							t.Fatalf("temporary downloads not cleaned up: %v, %v", leftover, err)
						}
					})
				}
			}
		}
	}
}

func TestReleaseChecksumManifest(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	script := ""
	checksumStep, publicationStep := -1, -1
	for i, step := range workflow.Jobs["build-and-release"].Steps {
		if step.Name == "Generate Release Checksums" {
			script, checksumStep = step.Run, i
		}
		if step.Name == "Create Release" {
			publicationStep = i
		}
	}
	if script == "" || publicationStep <= checksumStep {
		t.Fatal("checksums must be generated before publication")
	}
	dir := t.TempDir()
	dist := filepath.Join(dir, "dist")
	if err := os.Mkdir(dist, 0755); err != nil {
		t.Fatal(err)
	}
	binaries := []string{"cloak-linux-amd64", "cloak-linux-arm64", "cloak-darwin-amd64", "cloak-darwin-arm64", "cloak-windows-amd64.exe"}
	for _, name := range binaries {
		if err := os.WriteFile(filepath.Join(dist, name), []byte("binary: "+name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("checksum generation failed: %v\n%s", err, out)
	}
	manifest, err := os.ReadFile(filepath.Join(dist, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(manifest)), "\n")
	if len(lines) != len(binaries) {
		t.Fatalf("manifest has %d entries, want %d", len(lines), len(binaries))
	}
	for _, name := range binaries {
		digest := sha256.Sum256([]byte("binary: " + name))
		if !strings.Contains(string(manifest), fmt.Sprintf("%x  %s\n", digest, name)) {
			t.Fatalf("missing correct checksum for %s", name)
		}
	}
}
