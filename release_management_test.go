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

func TestPreviewInstallerVersionOrdering(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("installer regression test requires jq")
	}
	script, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	installDir := filepath.Join(dir, "install")
	if err := os.Mkdir(installDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, first, second, want string
	}{
		{
			"higher patch before later lower patch",
			`[{"tag_name":"v0.2.10-preview.20261011150000","prerelease":true,"draft":false,"published_at":"2026-10-11T15:00:00Z"}]`,
			`[{"tag_name":"v0.2.9-preview.20261011170000","prerelease":true,"draft":false,"published_at":"2026-10-11T17:00:00Z"}]`,
			"v0.2.10-preview.20261011150000",
		},
		{
			"timestamp order within patch",
			`[{"tag_name":"v0.2.0-preview.20261011160000","prerelease":true,"draft":false,"published_at":"2026-10-11T16:00:00Z"}]`,
			`[{"tag_name":"v0.2.0-preview.20261011150000","prerelease":true,"draft":false,"published_at":"2026-10-11T17:00:00Z"}]`,
			"v0.2.0-preview.20261011160000",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for name, body := range map[string]string{"page1": tc.first, "page2": tc.second} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			mock := `
uname() {
  if [[ "$1" == -s ]]; then echo Linux; else echo x86_64; fi
}
curl() {
  case "$2" in
    *"page=1") cat "$TEST_DIR/page1" ;;
    *"page=2") cat "$TEST_DIR/page2" ;;
    *"page=3") echo '[]' ;;
    *"/SHA256SUMS")
      printf '%s  cloak-linux-amd64\n' "$TEST_CHECKSUM" > "$4"
      ;;
    *"/download/"*)
      printf '%s\n' "$2" > "$TEST_DIR/download"
      printf '#!/usr/bin/env bash\necho "test version"\n' > "$4"
      ;;
    *) return 99 ;;
  esac
}
`
			localScript := strings.Replace(string(script), `INSTALL_DIR="/usr/local/bin"`, `INSTALL_DIR="`+installDir+`"`, 1)
			cmd := exec.Command("bash", "-c", mock+localScript, "install.sh", "--preview", "0.2")
			checksum := fmt.Sprintf("%x", sha256.Sum256([]byte("#!/usr/bin/env bash\necho \"test version\"\n")))
			cmd.Env = append(os.Environ(), "TEST_DIR="+dir, "TEST_CHECKSUM="+checksum)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("installer failed: %v\n%s", err, out)
			}
			download, err := os.ReadFile(filepath.Join(dir, "download"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(download), "/download/"+tc.want+"/") {
				t.Fatalf("download = %s, want %s", download, tc.want)
			}
		})
	}
}

func TestReleasePublicationAfterUploads(t *testing.T) {
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
	for _, step := range workflow.Jobs["build-and-release"].Steps {
		if step.Name == "Create Release" {
			script = step.Run
		}
	}
	if script == "" {
		t.Fatal("missing release publication script")
	}
	for _, preview := range []string{"false", "true"} {
		for _, failUpload := range []string{"false", "true"} {
			t.Run("preview="+preview+"/failUpload="+failUpload, func(t *testing.T) {
				dir := t.TempDir()
				if err := os.Mkdir(filepath.Join(dir, "dist"), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "dist", "cloak-linux-amd64"), []byte("binary"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "dist", "SHA256SUMS"), []byte("manifest"), 0600); err != nil {
					t.Fatal(err)
				}
				mock := `
gh() {
  printf '%s\n' "$*" >> "$TEST_DIR/commands"
  if [[ "$2" == upload && "$FAIL_UPLOAD" == true ]]; then
    return 1
  fi
}
`
				cmd := exec.Command("bash", "-c", mock+script)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(), "TEST_DIR="+dir, "FAIL_UPLOAD="+failUpload,
					"PREVIEW="+preview, "TAG_NAME=v0.2.0", "GITHUB_SHA=0123456789abcdef")
				out, err := cmd.CombinedOutput()
				if (err != nil) != (failUpload == "true") {
					t.Fatalf("publication error = %v\n%s", err, out)
				}
				data, err := os.ReadFile(filepath.Join(dir, "commands"))
				if err != nil {
					t.Fatal(err)
				}
				commands := strings.Split(strings.TrimSpace(string(data)), "\n")
				if len(commands) < 2 || !strings.HasPrefix(commands[0], "release create ") ||
					!strings.Contains(commands[0], "--draft") ||
					!strings.Contains(commands[0], "--target 0123456789abcdef") ||
					!strings.HasPrefix(commands[1], "release upload ") {
					t.Fatalf("incorrect draft/upload sequence: %v", commands)
				}
				if strings.Contains(commands[0], "--prerelease") != (preview == "true") {
					t.Fatalf("incorrect preview flag: %s", commands[0])
				}
				if !strings.Contains(commands[1], "dist/SHA256SUMS") ||
					!strings.Contains(commands[1], "dist/cloak-linux-amd64") {
					t.Fatalf("binary and manifest must be uploaded together: %s", commands[1])
				}
				if failUpload == "true" {
					if len(commands) != 2 {
						t.Fatalf("published despite upload failure: %v", commands)
					}
				} else {
					if len(commands) != 3 || !strings.HasPrefix(commands[2], "release edit ") ||
						!strings.Contains(commands[2], "--draft=false") {
						t.Fatalf("missing publication: %v", commands)
					}
					if strings.Contains(commands[2], "--latest=false") != (preview == "true") {
						t.Fatalf("incorrect latest flag: %s", commands[2])
					}
				}
			})
		}
	}
}
