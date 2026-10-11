package main

import (
	"testing"

	"github.com/ynotnauk/cloak/internal/updater"
)

func TestParseUpdateArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want updater.Options
		ok   bool
	}{
		{nil, updater.Options{}, true},
		{[]string{"--preview"}, updater.Options{Preview: true}, true},
		{[]string{"--preview", "0.2"}, updater.Options{Preview: true, Series: "0.2"}, true},
		{[]string{"0.2"}, updater.Options{}, false},
		{[]string{"--preview", "0.2", "0.3"}, updater.Options{}, false},
		{[]string{"--unknown"}, updater.Options{}, false},
	} {
		opts, err := parseUpdateArgs(tc.args)
		if (err == nil) != tc.ok {
			t.Errorf("parseUpdateArgs(%v) error = %v", tc.args, err)
		}
		if tc.ok && opts != tc.want {
			t.Errorf("parseUpdateArgs(%v) = %+v, want %+v", tc.args, opts, tc.want)
		}
	}
}
