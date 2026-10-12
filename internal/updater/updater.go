package updater

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	repoURL         = "https://api.github.com/repos/ynotnauk/cloak/releases"
	checkInterval   = 24 * time.Hour
	notifyInterval  = 24 * time.Hour
	checkTimeout    = 5 * time.Second
	updateTimeout   = 30 * time.Second
	downloadTimeout = 2 * time.Minute
)

type State struct {
	CurrentVersion string    `json:"current_version"`
	StableVersion  string    `json:"stable_version"`
	PreviewVersion string    `json:"preview_version"`
	LastChecked    time.Time `json:"last_checked"`
	LastNotified   time.Time `json:"last_notified"`
}

// Notice checks both channels for previews, and only stable releases otherwise.
func Notice(currentVersion string) (string, error) {
	if isIgnored(currentVersion) {
		return "", nil
	}
	state, err := fetchState(currentVersion)
	return formatNotice(currentVersion, state), err
}

func fetchState(current string) (State, error) {
	state := State{CurrentVersion: current}
	v, err := parseVersion(current)
	if err != nil {
		return state, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	state.StableVersion, err = fetchStable(ctx)
	if v.preview != "" {
		preview, previewErr := fetchPreview(ctx, v.series())
		state.PreviewVersion = preview
		err = errors.Join(err, previewErr)
	}
	if err == nil {
		state.LastChecked = time.Now()
	}
	return state, err
}

func formatNotice(current string, state State) string {
	v, err := parseVersion(current)
	if err != nil {
		return ""
	}
	var notice strings.Builder
	if v.preview != "" {
		fmt.Fprintf(&notice, "\n[notice] You are running a preview version of cloak: %s\n", current)
		latest, err := parseVersion(state.PreviewVersion)
		if err == nil && compareVersions(latest, v) > 0 {
			fmt.Fprintf(&notice, "[notice] A newer preview is available: %s\n[notice] To update your preview, run: cloak update --preview\n", state.PreviewVersion)
		}
	}
	latest, err := parseVersion(state.StableVersion)
	if err != nil {
		return notice.String()
	}
	if compareVersions(latest, v) > 0 {
		if v.preview == "" {
			fmt.Fprintf(&notice, "\n[notice] A new version of cloak is available: %s (current: %s)\n[notice] To update, run: cloak update\n", state.StableVersion, current)
		} else {
			fmt.Fprintf(&notice, "[notice] A stable release is available: %s\n[notice] To switch to stable, run: cloak update\n", state.StableVersion)
		}
	} else if v.preview != "" {
		fmt.Fprintf(&notice, "[notice] Latest stable is %s; cloak update switches to this older stable version.\n", state.StableVersion)
	}
	return notice.String()
}

// StartCheck runs passively in the background for regular commands.
func StartCheck(currentVersion string) func() {
	if isIgnored(currentVersion) {
		return func() {}
	}

	resultChan := make(chan string, 1)

	go func() {
		defer close(resultChan)

		notice, err := cachedNotice(currentVersion)
		if err != nil {
			notice += fmt.Sprintf("\n[notice] Update check failed: %v\n", err)
		}
		resultChan <- notice
	}()

	return func() {
		select {
		case msg := <-resultChan:
			if msg != "" {
				fmt.Fprint(os.Stderr, msg)
			}
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func isIgnored(ver string) bool {
	return os.Getenv("CLOAK_NO_UPDATE_CHECK") == "1" || ver == "dev" || ver == "" || strings.Contains(ver, "-dev-")
}

func getStateFilePath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "cloak", "update.json"), nil
}

func cachedNotice(current string) (string, error) {
	path, err := getStateFilePath()
	if err != nil {
		return "", err
	}
	state, err := loadState(path)
	if err != nil {
		return "", err
	}
	now := time.Now()
	if state.CurrentVersion != current {
		state = State{CurrentVersion: current}
	}
	if now.Sub(state.LastChecked) > checkInterval {
		lastNotified := state.LastNotified
		state, err = fetchState(current)
		state.LastNotified = lastNotified
	}
	notice := ""
	if now.Sub(state.LastNotified) > notifyInterval {
		notice = formatNotice(current, state)
		if notice != "" {
			state.LastNotified = now
		}
	}
	return notice, errors.Join(err, saveState(path, state))
}

func loadState(path string) (State, error) {
	var s State
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, fmt.Errorf("reading update cache: %w", err)
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, fmt.Errorf("decoding update cache: %w", err)
	}
	return s, nil
}

func saveState(path string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding update cache: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("creating update cache directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("writing update cache: %w", err)
	}
	return nil
}

type release struct {
	TagName string `json:"tag_name"`
	Preview bool   `json:"prerelease"`
	Draft   bool   `json:"draft"`
}

func fetchJSON(ctx context.Context, url string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "cloak-cli")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching releases: HTTP %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("decoding releases: %w", err)
	}
	return nil
}

func fetchStable(ctx context.Context) (string, error) {
	var r release
	if err := fetchJSON(ctx, repoURL+"/latest", &r); err != nil {
		return "", err
	}
	if r.Preview || r.Draft {
		return "", fmt.Errorf("latest stable endpoint returned a draft or prerelease")
	}
	v, err := parseVersion(r.TagName)
	if err != nil {
		return "", err
	}
	if v.preview != "" {
		return "", fmt.Errorf("latest stable endpoint returned a preview tag")
	}
	return r.TagName, nil
}

func fetchPreview(ctx context.Context, series string) (string, error) {
	latest := ""
	var latestVersion version
	for page := 1; ; page++ {
		var releases []release
		url := fmt.Sprintf("%s?per_page=100&page=%d", repoURL, page)
		if err := fetchJSON(ctx, url, &releases); err != nil {
			return "", err
		}
		if len(releases) == 0 {
			break
		}
		for _, r := range releases {
			if !r.Preview || r.Draft || !strings.HasPrefix(r.TagName, "v"+series+".") || !strings.Contains(r.TagName, "-preview.") {
				continue
			}
			v, err := parseVersion(r.TagName)
			if err != nil {
				return "", err
			}
			if latest == "" || compareVersions(v, latestVersion) > 0 {
				latest, latestVersion = r.TagName, v
			}
		}
	}
	if latest == "" {
		return "", fmt.Errorf("no preview release found for %s", series)
	}
	return latest, nil
}

// Upgrade downloads the latest release binary and replaces the current executable.
func Upgrade(currentVersion string, opts Options) error {
	series, err := previewSeries(currentVersion, opts)
	if err != nil {
		return err
	}
	fmt.Println("Checking for latest release...")
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()
	var latest string
	if opts.Preview {
		latest, err = fetchPreview(ctx, series)
	} else {
		latest, err = fetchStable(ctx)
	}
	if err != nil {
		return fmt.Errorf("failed fetching latest version: %w", err)
	}

	if latest == currentVersion && currentVersion != "dev" {
		fmt.Printf("cloak is already up to date (%s)\n", currentVersion)
		return nil
	}
	if current, err := parseVersion(currentVersion); err == nil {
		target, err := parseVersion(latest)
		if err != nil {
			return err
		}
		if !opts.Preview && current.preview != "" {
			fmt.Printf("Switching from preview %s to stable %s.\n", currentVersion, latest)
		}
		if compareVersions(target, current) < 0 {
			if opts.Preview {
				return fmt.Errorf("latest preview %s is older than installed %s; refusing to downgrade", latest, currentVersion)
			}
			fmt.Printf("Warning: %s is older than installed %s.\n", latest, currentVersion)
		}
	}

	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	binaryName := fmt.Sprintf("cloak-%s-%s%s", runtime.GOOS, runtime.GOARCH, ext)
	releaseURL := fmt.Sprintf("https://github.com/ynotnauk/cloak/releases/download/%s", latest)

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not resolve executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("could not resolve symlink: %w", err)
	}

	fmt.Printf("Downloading %s (%s)...\n", latest, binaryName)
	downloadCtx, downloadCancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer downloadCancel()
	if err := downloadVerifiedBinary(downloadCtx, execPath, releaseURL, binaryName); err != nil {
		return err
	}
	fmt.Printf("Successfully updated cloak to %s!\n", latest)
	return nil
}

func downloadAsset(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cloak-cli")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download failed for %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("release asset not found at %s (HTTP %d)", url, resp.StatusCode)
	}
	return resp, nil
}

func downloadVerifiedBinary(ctx context.Context, execPath, releaseURL, binaryName string) error {
	manifest, err := downloadAsset(ctx, releaseURL+"/SHA256SUMS")
	if err != nil {
		return fmt.Errorf("checksum verification requires SHA256SUMS: %w", err)
	}
	defer func() { _ = manifest.Body.Close() }()
	const maxManifestSize = 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(manifest.Body, maxManifestSize+1))
	if err != nil {
		return fmt.Errorf("failed reading SHA256SUMS: %w", err)
	}
	if len(data) > maxManifestSize {
		return fmt.Errorf("SHA256SUMS exceeds maximum size")
	}
	checksum, err := releaseChecksum(string(data), binaryName)
	if err != nil {
		return err
	}
	binary, err := downloadAsset(ctx, releaseURL+"/"+binaryName)
	if err != nil {
		return err
	}
	defer func() { _ = binary.Body.Close() }()
	return replaceBinary(execPath, binary.Body, checksum)
}

func releaseChecksum(manifest, binaryName string) (string, error) {
	scanner := bufio.NewScanner(strings.NewReader(manifest))
	checksum := ""
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || len(fields[0]) != sha256.Size*2 {
			return "", fmt.Errorf("malformed SHA256SUMS entry")
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			return "", fmt.Errorf("invalid SHA256SUMS digest: %w", err)
		}
		if strings.TrimPrefix(fields[1], "*") == binaryName {
			if checksum != "" {
				return "", fmt.Errorf("duplicate SHA256SUMS entry for %s", binaryName)
			}
			checksum = strings.ToLower(fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed parsing SHA256SUMS: %w", err)
	}
	if checksum == "" {
		return "", fmt.Errorf("SHA256SUMS has no entry for %s", binaryName)
	}
	return checksum, nil
}

func replaceBinary(execPath string, binary io.Reader, checksum string) error {
	// Write to temporary file next to executable for atomic rename
	tmpFile, err := os.CreateTemp(filepath.Dir(execPath), "cloak-upgrade-*")
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("permission denied writing to %s (try running with sudo)", filepath.Dir(execPath))
		}
		return err
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmpFile, hash), binary)
	if err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed saving binary: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed saving binary: %w", err)
	}
	if size == 0 {
		return fmt.Errorf("downloaded release binary is empty")
	}
	if actual := hex.EncodeToString(hash.Sum(nil)); actual != checksum {
		return fmt.Errorf("release binary SHA-256 checksum mismatch: expected %s, got %s", checksum, actual)
	}

	if err := os.Chmod(tmpFile.Name(), 0755); err != nil {
		return err
	}

	// Atomic replace
	if err := os.Rename(tmpFile.Name(), execPath); err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("permission denied replacing %s (try running with sudo)", execPath)
		}
		return fmt.Errorf("failed replacing binary: %w", err)
	}

	return nil
}
