// Package envelope defines the Cloak ciphertext wire format and its strict
// validation.
//
// Format (v1, unfrozen until the first release):
//
//	CLOAK[v1,iv:<b64>,data:<b64>,wrap:<epk>.<iv>.<key>[,wrap:...]]
//
// All binary fields use unpadded URL-safe base64. Fields appear in exactly this
// order and at least one wrap is required.
package envelope

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	Open    = "CLOAK["
	Version = "v1"

	IVSize      = 12
	TagSize     = 16
	PubKeySize  = 32
	WrappedSize = 32 + TagSize
	MaxWraps    = 1024
)

// legacyPrefixes are pre-release formats that are no longer supported. They
// stay reserved so that they fail loudly instead of being treated as plaintext.
var legacyPrefixes = []string{"CLOAK:v", "CLOAK:YAML:"}

var ErrMalformed = errors.New("malformed cloak envelope")

type Wrap struct {
	EphemeralPub []byte
	IV           []byte
	Key          []byte
}

type Envelope struct {
	IV    []byte
	Data  []byte
	Wraps []Wrap
}

var enc = base64.RawURLEncoding

func (e *Envelope) String() string {
	var b strings.Builder
	b.WriteString(Open + Version + ",iv:")
	b.WriteString(enc.EncodeToString(e.IV))
	b.WriteString(",data:")
	b.WriteString(enc.EncodeToString(e.Data))
	for _, w := range e.Wraps {
		b.WriteString(",wrap:")
		b.WriteString(enc.EncodeToString(w.EphemeralPub))
		b.WriteByte('.')
		b.WriteString(enc.EncodeToString(w.IV))
		b.WriteByte('.')
		b.WriteString(enc.EncodeToString(w.Key))
	}
	b.WriteByte(']')
	return b.String()
}

// Reserved reports whether s starts with a prefix reserved for Cloak envelopes.
func Reserved(s string) bool {
	if strings.HasPrefix(s, Open) {
		return true
	}
	for _, p := range legacyPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// ContainsReserved reports whether content mentions any reserved prefix anywhere.
func ContainsReserved(content string) bool {
	if strings.Contains(content, Open) {
		return true
	}
	for _, p := range legacyPrefixes {
		if strings.Contains(content, p) {
			return true
		}
	}
	return false
}

// Check classifies a single value. It returns (true, nil) for a structurally
// valid envelope, (false, nil) for ordinary plaintext and (false, err) for a
// reserved-prefix value that is not a valid envelope.
//
// A plaintext that is itself a structurally valid envelope cannot be told apart
// from ciphertext; such values are reserved and cannot be stored as secrets.
func Check(s string) (bool, error) {
	if !Reserved(s) {
		return false, nil
	}
	if _, err := Parse(s); err != nil {
		return false, err
	}
	return true, nil
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

// Parse strictly validates and decodes an envelope.
func Parse(s string) (*Envelope, error) {
	for _, p := range legacyPrefixes {
		if strings.HasPrefix(s, p) {
			return nil, fmt.Errorf("%w: unsupported pre-release envelope format; decrypt it with the version that created it and re-encrypt", ErrMalformed)
		}
	}
	body, ok := strings.CutPrefix(s, Open)
	if !ok {
		return nil, malformed("missing %q prefix", Open)
	}
	body, ok = strings.CutSuffix(body, "]")
	if !ok {
		return nil, malformed("missing closing ']' (truncated?)")
	}

	fields := strings.Split(body, ",")
	if len(fields) < 4 {
		return nil, malformed("expected version, iv, data and at least one wrap")
	}
	if fields[0] != Version {
		return nil, malformed("unsupported version %q", fields[0])
	}
	if len(fields)-3 > MaxWraps {
		return nil, malformed("too many recipient wraps")
	}

	e := &Envelope{}
	var err error
	if e.IV, err = field(fields[1], "iv"); err != nil {
		return nil, err
	}
	if len(e.IV) != IVSize {
		return nil, malformed("iv must be %d bytes", IVSize)
	}
	if e.Data, err = field(fields[2], "data"); err != nil {
		return nil, err
	}
	if len(e.Data) < TagSize {
		return nil, malformed("data is shorter than the authentication tag")
	}

	for _, f := range fields[3:] {
		raw, ok := strings.CutPrefix(f, "wrap:")
		if !ok {
			return nil, malformed("unexpected field %q", truncate(f))
		}
		parts := strings.Split(raw, ".")
		if len(parts) != 3 {
			return nil, malformed("wrap must have three segments")
		}
		var w Wrap
		for i, dst := range []*[]byte{&w.EphemeralPub, &w.IV, &w.Key} {
			if *dst, err = decode(parts[i]); err != nil {
				return nil, malformed("wrap segment %d: invalid base64", i+1)
			}
		}
		if len(w.EphemeralPub) != PubKeySize || len(w.IV) != IVSize || len(w.Key) != WrappedSize {
			return nil, malformed("wrap has invalid segment lengths")
		}
		e.Wraps = append(e.Wraps, w)
	}
	return e, nil
}

func field(f, name string) ([]byte, error) {
	raw, ok := strings.CutPrefix(f, name+":")
	if !ok {
		return nil, malformed("expected field %q, got %q", name, truncate(f))
	}
	b, err := decode(raw)
	if err != nil {
		return nil, malformed("%s: invalid base64", name)
	}
	return b, nil
}

// decode is strict: it rejects padding and non-canonical trailing bits.
func decode(s string) ([]byte, error) {
	return enc.Strict().DecodeString(s)
}

func truncate(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}
