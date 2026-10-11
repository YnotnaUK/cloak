package updater

import (
	"fmt"
	"regexp"
	"strings"
)

var versionPattern = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-preview\.([0-9]{14}))?$`)
var seriesPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

type version struct {
	major, minor, patch string
	preview             string
	legacy              bool
}

func parseVersion(tag string) (version, error) {
	match := versionPattern.FindStringSubmatch(tag)
	if match == nil {
		return version{}, fmt.Errorf("unsupported release version %q", tag)
	}
	v := version{major: match[1], minor: match[2], patch: match[3], preview: match[4]}
	// Older stable builds used major.minor.<14-digit timestamp>.
	if v.preview == "" && len(v.patch) == 14 {
		v.legacy = true
	}
	return v, nil
}

func (v version) series() string {
	return v.major + "." + v.minor
}

func compareNumber(a, b string) int {
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return strings.Compare(a, b)
}

func compareVersions(a, b version) int {
	for _, pair := range [][2]string{{a.major, b.major}, {a.minor, b.minor}} {
		if cmp := compareNumber(pair[0], pair[1]); cmp != 0 {
			return cmp
		}
	}
	if a.legacy != b.legacy {
		if a.legacy {
			return -1
		}
		return 1
	}
	if cmp := compareNumber(a.patch, b.patch); cmp != 0 {
		return cmp
	}
	if a.preview == "" && b.preview != "" {
		return 1
	}
	if a.preview != "" && b.preview == "" {
		return -1
	}
	return strings.Compare(a.preview, b.preview)
}

type Options struct {
	Preview bool
	Series  string
}

func previewSeries(current string, opts Options) (string, error) {
	if !opts.Preview {
		if opts.Series != "" {
			return "", fmt.Errorf("a release series requires --preview")
		}
		return "", nil
	}
	if opts.Series != "" {
		if !seriesPattern.MatchString(opts.Series) {
			return "", fmt.Errorf("preview series must be major.minor (for example, 0.2)")
		}
		return opts.Series, nil
	}
	v, err := parseVersion(current)
	if err != nil || v.preview == "" {
		return "", fmt.Errorf("specify a preview series when not running a preview: cloak update --preview 0.2")
	}
	return v.series(), nil
}
