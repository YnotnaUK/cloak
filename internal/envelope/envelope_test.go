package envelope_test

import (
	"strings"
	"testing"

	"github.com/ynotnauk/cloak/internal/envelope"
)

func valid() *envelope.Envelope {
	return &envelope.Envelope{
		IV:   make([]byte, envelope.IVSize),
		Data: make([]byte, envelope.TagSize+4),
		Wraps: []envelope.Wrap{{
			EphemeralPub: make([]byte, envelope.PubKeySize),
			IV:           make([]byte, envelope.IVSize),
			Key:          make([]byte, envelope.WrappedSize),
		}},
	}
}

func TestRoundTrip(t *testing.T) {
	e := valid()
	e.Wraps = append(e.Wraps, e.Wraps[0])
	s := e.String()
	got, err := envelope.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != s || len(got.Wraps) != 2 {
		t.Fatalf("round trip mismatch: %q", got.String())
	}
}

func TestCheck(t *testing.T) {
	good := valid().String()
	tests := []struct {
		name    string
		in      string
		want    bool
		wantErr bool
	}{
		{"plaintext", "hunter2", false, false},
		{"empty", "", false, false},
		{"valid", good, true, false},
		{"truncated", good[:len(good)-1], false, true},
		{"cut mid-field", good[:20], false, true},
		{"trailing data", good + "x", false, true},
		{"leading space", " " + good, false, false},
		{"bad version", strings.Replace(good, "v1", "v2", 1), false, true},
		{"missing wrap", strings.Join(strings.Split(good, ",")[:3], ",") + "]", false, true},
		{"reordered", strings.Replace(good, "iv:", "xx:", 1), false, true},
		{"padding", strings.Replace(good, ",data:", ",data:=", 1), false, true},
		{"short iv", strings.Replace(good, "iv:AAAAAAAAAAAAAAAA", "iv:AAAA", 1), false, true},
		{"legacy v1", "CLOAK:v1:aa:bb|cc", false, true},
		{"legacy yaml", "CLOAK:YAML:v1:CLOAK:v1:x", false, true},
		{"unrelated CLOAK", "CLOAKED", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := envelope.Check(tc.in)
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("Check = (%v, %v), want (%v, err=%v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	f.Add(valid().String())
	f.Add("CLOAK[v1,iv:,data:,wrap:..]")
	f.Add("CLOAK[")
	f.Fuzz(func(t *testing.T, s string) {
		e, err := envelope.Parse(s)
		if err != nil {
			return
		}
		if e.String() != s {
			t.Fatalf("accepted non-canonical input %q (re-encodes as %q)", s, e.String())
		}
	})
}
