package updater

import (
	"context"
	"encoding/json"
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
	repoURL        = "https://api.github.com/repos/ynotnauk/cloak/releases/latest"
	checkInterval  = 24 * time.Hour
	notifyInterval = 24 * time.Hour
	httpTimeout    = 1500 * time.Millisecond
)

type State struct {
	LatestVersion string    `json:"latest_version"`
	LastChecked   time.Time `json:"last_checked"`
	LastNotified  time.Time `json:"last_notified"`
}

// CheckLatest fetches the newest release from GitHub, updates state, and returns if newer.
func CheckLatest(currentVersion string) (string, bool) {
	if isIgnored(currentVersion) {
		return "", false
	}

	latest, err := fetchLatestVersion()
	if err != nil || latest == "" {
		return "", false
	}

	// Update cached latest version
	if stateFile, err := getStateFilePath(); err == nil {
		state := loadState(stateFile)
		state.LatestVersion = latest
		state.LastChecked = time.Now()
		saveState(stateFile, state)
	}

	return latest, latest != currentVersion
}

// StartCheck runs passively in the background for regular commands.
func StartCheck(currentVersion string) func() {
	if isIgnored(currentVersion) {
		return func() {}
	}

	resultChan := make(chan string, 1)

	go func() {
		defer close(resultChan)

		stateFile, err := getStateFilePath()
		if err != nil {
			return
		}

		state := loadState(stateFile)
		now := time.Now()

		// 1. Fetch if checked > 24 hours ago using CheckLatest
		if now.Sub(state.LastChecked) > checkInterval {
			if latest, _ := CheckLatest(currentVersion); latest != "" {
				state.LatestVersion = latest
			}
		}

		// 2. Queue notice if an update is available and notification cooldown passed
		if state.LatestVersion != "" && state.LatestVersion != currentVersion {
			if now.Sub(state.LastNotified) > notifyInterval {
				state.LastNotified = now
				saveState(stateFile, state)

				resultChan <- fmt.Sprintf(
					"\n[notice] A new version of cloak is available: %s (current: %s)\n"+
						"[notice] To update, run: cloak update\n",
					state.LatestVersion, currentVersion,
				)
			}
		}
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
	return os.Getenv("CLOAK_NO_UPDATE_CHECK") == "1" || ver == "dev" || ver == ""
}

func getStateFilePath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "cloak", "update.json"), nil
}

func loadState(path string) State {
	var s State
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &s)
	}
	return s
}

func saveState(path string, s State) {
	if data, err := json.MarshalIndent(s, "", "  "); err == nil {
		_ = os.WriteFile(path, data, 0600)
	}
}

func fetchLatestVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, repoURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "cloak-cli")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}

	return strings.TrimSpace(release.TagName), nil
}

// Upgrade downloads the latest release binary and replaces the current executable.
func Upgrade(currentVersion string) error {
	fmt.Println("Checking for latest release...")
	latest, err := fetchLatestVersion()
	if err != nil {
		return fmt.Errorf("failed fetching latest version: %w", err)
	}

	if latest == currentVersion && currentVersion != "dev" {
		fmt.Printf("cloak is already up to date (%s)\n", currentVersion)
		return nil
	}

	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	binaryName := fmt.Sprintf("cloak-%s-%s%s", runtime.GOOS, runtime.GOARCH, ext)
	downloadURL := fmt.Sprintf("https://github.com/ynotnauk/cloak/releases/download/%s/%s", latest, binaryName)

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not resolve executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("could not resolve symlink: %w", err)
	}

	fmt.Printf("Downloading %s (%s)...\n", latest, binaryName)
	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("release asset not found at %s (HTTP %d)", downloadURL, resp.StatusCode)
	}

	// Write to temporary file next to executable for atomic rename
	tmpFile, err := os.CreateTemp(filepath.Dir(execPath), "cloak-upgrade-*")
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("permission denied writing to %s (try running with sudo)", filepath.Dir(execPath))
		}
		return err
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed saving binary: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed saving binary: %w", err)
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

	fmt.Printf("Successfully updated cloak to %s!\n", latest)
	return nil
}
