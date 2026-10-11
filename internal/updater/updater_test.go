package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"v0.1.0", "v0.1.0", 0},
		{"v0.1.1", "v0.1.0", 1},
		{"v0.1.0", "v0.2.0-preview.20261011155536", -1},
		{"v0.2.0", "v0.2.0-preview.20261011155536", 1},
		{"v0.2.0-preview.20261011160000", "v0.2.0-preview.20261011155536", 1},
		{"v0.2.1-preview.20261011155536", "v0.2.0-preview.20261011160000", 1},
		{"v0.1.20260928150402", "v0.1.20260927150402", 1},
		{"v0.1.0", "v0.1.20260928150402", 1},
		{"v0.1.20260928150402", "v0.2.0-preview.20261011155536", -1},
		{"v0.99999999999999999999.0", "v0.2.0", 1},
	} {
		t.Run(tc.a+"/"+tc.b, func(t *testing.T) {
			a, err := parseVersion(tc.a)
			if err != nil {
				t.Fatal(err)
			}
			b, err := parseVersion(tc.b)
			if err != nil {
				t.Fatal(err)
			}
			if got := compareVersions(a, b); got != tc.want {
				t.Fatalf("compare = %d, want %d", got, tc.want)
			}
		})
	}
	for _, invalid := range []string{"", "dev", "v0.2", "v00.2.0", "v0.2.0-preview.sha", "v0.2.0-preview.123"} {
		if _, err := parseVersion(invalid); err == nil {
			t.Errorf("accepted invalid version %q", invalid)
		}
	}
}

func TestPreviewSeries(t *testing.T) {
	for _, tc := range []struct {
		current string
		opts    Options
		want    string
		ok      bool
	}{
		{"v0.1.0", Options{}, "", true},
		{"v0.2.0-preview.20261011155536", Options{Preview: true}, "0.2", true},
		{"v0.1.0", Options{Preview: true, Series: "0.2"}, "0.2", true},
		{"dev", Options{Preview: true, Series: "0.2"}, "0.2", true},
		{"v0.1.0", Options{Preview: true}, "", false},
		{"v0.1.0", Options{Series: "0.2"}, "", false},
		{"v0.1.0", Options{Preview: true, Series: "0.02"}, "", false},
	} {
		got, err := previewSeries(tc.current, tc.opts)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("previewSeries(%q, %+v) = %q, %v", tc.current, tc.opts, got, err)
		}
	}
}

func TestFormatNotice(t *testing.T) {
	const preview = "v0.2.0-preview.20261011155536"
	for _, tc := range []struct {
		name, current, stable, preview string
		want, absent                   []string
	}{
		{"stable update", "v0.1.0", "v0.1.1", "", []string{"A new version", "cloak update"}, []string{"preview"}},
		{"same stable", "v0.1.0", "v0.1.0", "", nil, []string{"[notice]"}},
		{"older stable", "v0.2.0", "v0.1.0", "", nil, []string{"[notice]"}},
		{"preview behind stable", preview, "v0.1.0", preview, []string{"running a preview", "older stable"}, []string{"A new version", "A stable release is available", "newer preview"}},
		{"preview promotion", preview, "v0.2.0", preview, []string{"running a preview", "A stable release is available", "switch to stable"}, []string{"older stable"}},
		{"both updates", preview, "v0.3.0", "v0.2.1-preview.20261011160000", []string{"newer preview", "cloak update --preview", "A stable release"}, nil},
		{"preview reminder without network", preview, "", "", []string{"running a preview"}, []string{"cloak update"}},
		{"legacy stable update", "v0.1.20260928150402", "v0.1.0", "", []string{"A new version"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := formatNotice(tc.current, State{StableVersion: tc.stable, PreviewVersion: tc.preview})
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("notice %q lacks %q", got, want)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(got, absent) {
					t.Errorf("notice %q contains %q", got, absent)
				}
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func mockHTTP(t *testing.T, handler roundTripFunc) {
	t.Helper()
	previous := http.DefaultClient.Transport
	http.DefaultClient.Transport = handler
	t.Cleanup(func() { http.DefaultClient.Transport = previous })
}

func response(body string, status int) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}
}

func TestReleaseDiscovery(t *testing.T) {
	var pages []string
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("missing User-Agent")
		}
		if r.URL.Path == "/repos/ynotnauk/cloak/releases/latest" {
			return response(`{"tag_name":"v0.1.0"}`, 200), nil
		}
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		var releases []release
		switch page {
		case "1":
			releases = []release{
				{TagName: "v0.3.0-preview.20261011170000", Preview: true},
				{TagName: "v0.2.0-preview.20261011160000", Preview: true},
				{TagName: "v0.2.9-preview.20261011160000", Preview: true, Draft: true},
				{TagName: "v0.2.5", Preview: false},
			}
		case "2":
			releases = []release{{TagName: "v0.2.1-preview.20261011155536", Preview: true}}
		}
		body, err := json.Marshal(releases)
		if err != nil {
			t.Fatal(err)
		}
		return response(string(body), 200), nil
	})
	stable, err := fetchStable(context.Background())
	if err != nil || stable != "v0.1.0" {
		t.Fatalf("stable = %q, %v", stable, err)
	}
	preview, err := fetchPreview(context.Background(), "0.2")
	if err != nil || preview != "v0.2.1-preview.20261011155536" {
		t.Fatalf("preview = %q, %v", preview, err)
	}
	if strings.Join(pages, ",") != "1,2,3" {
		t.Fatalf("pages = %v", pages)
	}
}

func TestDiscoveryFailures(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		preview    bool
	}{
		{"HTTP error", `{}`, 500, false},
		{"bad JSON", `invalid`, 200, false},
		{"missing tag", `{}`, 200, false},
		{"preview as stable", `{"tag_name":"v0.2.0-preview.20261011155536"}`, 200, false},
		{"prerelease as stable", `{"tag_name":"v0.2.0","prerelease":true}`, 200, false},
		{"no previews", `[]`, 200, true},
		{"preview HTTP error", `{}`, 403, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockHTTP(t, func(*http.Request) (*http.Response, error) {
				return response(tc.body, tc.status), nil
			})
			var err error
			if tc.preview {
				_, err = fetchPreview(context.Background(), "0.2")
			} else {
				_, err = fetchStable(context.Background())
			}
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestCachedNotice(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path, err := getStateFilePath()
	if err != nil {
		t.Fatal(err)
	}
	const current = "v0.2.0-preview.20261011155536"
	calls := 0
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if strings.HasSuffix(r.URL.Path, "/latest") {
			return response(`{"tag_name":"v0.2.0"}`, 200), nil
		}
		if r.URL.Query().Get("page") == "1" {
			return response(`[{"tag_name":"v0.2.0-preview.20261011155536","prerelease":true}]`, 200), nil
		}
		return response(`[]`, 200), nil
	})
	notice, err := cachedNotice(current)
	if err != nil || !strings.Contains(notice, "running a preview") {
		t.Fatalf("first notice = %q, %v", notice, err)
	}
	state, err := loadState(path)
	if err != nil || state.CurrentVersion != current || state.LastChecked.IsZero() {
		t.Fatalf("state = %+v, %v", state, err)
	}
	if notice, err := cachedNotice(current); err != nil || notice != "" || calls != 3 {
		t.Fatalf("cooldown notice = %q, %v, calls=%d", notice, err, calls)
	}
	state.LastNotified = time.Now().Add(-25 * time.Hour)
	if err := saveState(path, state); err != nil {
		t.Fatal(err)
	}
	if notice, err := cachedNotice(current); err != nil || notice == "" || calls != 3 {
		t.Fatalf("reminder = %q, %v, calls=%d", notice, err, calls)
	}
	if notice, err := cachedNotice("v0.1.0"); err != nil || !strings.Contains(notice, "A new version") || calls != 4 {
		t.Fatalf("channel change = %q, %v, calls=%d", notice, err, calls)
	}
}

func TestFailedCheckReminderCooldown(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	mockHTTP(t, func(*http.Request) (*http.Response, error) {
		return response(`{}`, http.StatusServiceUnavailable), nil
	})
	const current = "v0.2.0-preview.20261011155536"
	notice, err := cachedNotice(current)
	if err == nil || !strings.Contains(notice, "running a preview") {
		t.Fatalf("first failed check = %q, %v", notice, err)
	}
	path, err := getStateFilePath()
	if err != nil {
		t.Fatal(err)
	}
	state, err := loadState(path)
	if err != nil || state.LastNotified.IsZero() || !state.LastChecked.IsZero() {
		t.Fatalf("failed check cache = %+v, %v", state, err)
	}
	notice, err = cachedNotice(current)
	if err == nil || notice != "" {
		t.Fatalf("repeated failed check bypassed cooldown: %q, %v", notice, err)
	}
}

func TestExplicitPreviewUpdateTimeout(t *testing.T) {
	calls := 0
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		calls++
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) < 20*time.Second {
			t.Error("explicit update lacks a sufficient shared pagination timeout")
		}
		if r.URL.Query().Get("page") == "1" {
			return response(`[{"tag_name":"v0.2.0-preview.20261011155536","prerelease":true}]`, 200), nil
		}
		return response(`[]`, 200), nil
	})
	if err := Upgrade("v0.2.0-preview.20261011155536", Options{Preview: true}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("pagination calls = %d, want 2", calls)
	}
}

func TestCacheErrorsAndIgnoredVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update.json")
	if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(path); err == nil {
		t.Error("corrupt cache was ignored")
	}
	if err := saveState(filepath.Join(path, "child"), State{}); err == nil {
		t.Error("cache write failure was ignored")
	}
	mockHTTP(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("ignored version made an HTTP request")
		return nil, fmt.Errorf("unexpected HTTP request")
	})
	for _, current := range []string{"dev", "", "v0.2.0-dev-abc123"} {
		if notice, err := Notice(current); err != nil || notice != "" {
			t.Errorf("ignored notice = %q, %v", notice, err)
		}
		StartCheck(current)()
	}
	t.Setenv("CLOAK_NO_UPDATE_CHECK", "1")
	if notice, err := Notice("v0.1.0"); err != nil || notice != "" {
		t.Errorf("disabled notice = %q, %v", notice, err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, fmt.Errorf("interrupted download")
}

func TestReplaceBinary(t *testing.T) {
	for _, tc := range []struct {
		name string
		body io.Reader
		ok   bool
	}{
		{"complete download", strings.NewReader("new binary"), true},
		{"empty download", strings.NewReader(""), false},
		{"interrupted download", io.MultiReader(strings.NewReader("partial"), failingReader{}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "cloak")
			if err := os.WriteFile(path, []byte("old binary"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := replaceBinary(path, tc.body); (err == nil) != tc.ok {
				t.Fatalf("replacement error = %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want := "old binary"
			if tc.ok {
				want = "new binary"
			}
			if string(data) != want {
				t.Fatalf("binary = %q, want %q", data, want)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("temporary files not cleaned up: %v, %v", entries, err)
			}
		})
	}
}

func TestNoticeFetchesChannels(t *testing.T) {
	calls := 0
	mockHTTP(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if strings.HasSuffix(r.URL.Path, "/latest") {
			return response(`{"tag_name":"v0.2.0"}`, 200), nil
		}
		if r.URL.Query().Get("page") == "1" {
			return response(`[{"tag_name":"v0.2.1-preview.20261011160000","prerelease":true}]`, 200), nil
		}
		return response(`[]`, 200), nil
	})
	notice, err := Notice("v0.1.0")
	if err != nil || calls != 1 || !strings.Contains(notice, "A new version") {
		t.Fatalf("stable notice = %q, %v; calls=%d", notice, err, calls)
	}
	notice, err = Notice("v0.2.0-preview.20261011155536")
	if err != nil || calls != 4 || !strings.Contains(notice, "newer preview") || !strings.Contains(notice, "A stable release") {
		t.Fatalf("preview notice = %q, %v; calls=%d", notice, err, calls)
	}
}

func TestUpgradeWithoutReplacement(t *testing.T) {
	for _, tc := range []struct {
		name, current, tag string
		opts               Options
		wantError          bool
	}{
		{"stable current", "v0.1.0", "v0.1.0", Options{}, false},
		{"preview current", "v0.2.0-preview.20261011155536", "v0.2.0-preview.20261011155536", Options{Preview: true}, false},
		{"older preview", "v0.2.1-preview.20261011155536", "v0.2.0-preview.20261011155536", Options{Preview: true}, true},
		{"missing preview", "v0.1.0", "", Options{Preview: true, Series: "0.2"}, true},
		{"series required", "v0.1.0", "", Options{Preview: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockHTTP(t, func(r *http.Request) (*http.Response, error) {
				if strings.Contains(r.URL.Path, "/download/") {
					t.Fatal("unexpected binary download")
				}

				if strings.HasSuffix(r.URL.Path, "/latest") {
					body, _ := json.Marshal(release{TagName: tc.tag})
					return response(string(body), 200), nil
				}
				if tc.tag != "" && r.URL.Query().Get("page") == "1" {
					body, _ := json.Marshal([]release{{TagName: tc.tag, Preview: true}})
					return response(string(body), 200), nil
				}
				return response(`[]`, 200), nil
			})
			if err := Upgrade(tc.current, tc.opts); (err != nil) != tc.wantError {
				t.Errorf("Upgrade error = %v", err)
			}
		})
	}
}
