// SPDX-License-Identifier: Apache-2.0

package reporting

import (
	"encoding/json"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// clean makes one untrusted string safe to place in line-oriented text. It
// removes ANSI escape sequences, control characters, and bidirectional
// override characters, and turns line breaks and tabs into single spaces.
// Format-specific escaping (Markdown, HTML) is applied on top of this.
func clean(s string) string {
	if s == "" {
		return s
	}
	if isPlain(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	rs := []rune(strings.ToValidUTF8(s, string(utf8.RuneError)))
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == 0x1b:
			i = skipEscape(rs, i)
		case r == 0x9b: // single-character CSI
			i = skipCSI(rs, i+1)
		case r == '\n' || r == '\t' || r == 0x2028 || r == 0x2029 || r == 0x85:
			b.WriteByte(' ')
		case unicode.IsControl(r):
			// dropped, including carriage return and the C1 range
		case isBidiControl(r):
			// dropped: these can reorder displayed text
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isPlain(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

func isBidiControl(r rune) bool {
	switch {
	case r == 0x061c, r == 0x200e, r == 0x200f:
		return true
	case r >= 0x202a && r <= 0x202e:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// skipEscape returns the index of the last rune of the escape sequence that
// starts at rs[i] (an ESC character).
func skipEscape(rs []rune, i int) int {
	if i+1 >= len(rs) {
		return i
	}
	switch rs[i+1] {
	case '[':
		return skipCSI(rs, i+2)
	case ']', 'P', 'X', '^', '_':
		// OSC, DCS, SOS, PM, APC: run to BEL or the string terminator.
		for j := i + 2; j < len(rs); j++ {
			if rs[j] == 0x07 || rs[j] == 0x9c {
				return j
			}
			if rs[j] == 0x1b {
				if j+1 < len(rs) && rs[j+1] == '\\' {
					return j + 1
				}
				return j - 1
			}
			if rs[j] == '\n' {
				return j - 1
			}
		}
		return len(rs) - 1
	default:
		// Two-character sequence, possibly with intermediate bytes.
		j := i + 1
		for j < len(rs) && rs[j] >= 0x20 && rs[j] <= 0x2f {
			j++
		}
		if j < len(rs) && rs[j] >= 0x30 && rs[j] <= 0x7e {
			return j
		}
		return j - 1
	}
}

// skipCSI consumes CSI parameter and intermediate bytes starting at rs[j] and
// returns the index of the final byte.
func skipCSI(rs []rune, j int) int {
	for j < len(rs) && rs[j] >= 0x20 && rs[j] <= 0x3f {
		j++
	}
	if j < len(rs) && rs[j] >= 0x40 && rs[j] <= 0x7e {
		return j
	}
	return j - 1
}

// copyResult returns a deep copy of res in which nil slices and maps are
// replaced by empty ones, so that consumers always see arrays and objects.
func copyResult(res *model.ScanResult) (*model.ScanResult, error) {
	data, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	out := new(model.ScanResult)
	if err := json.Unmarshal(data, out); err != nil {
		return nil, err
	}
	walk(reflect.ValueOf(out).Elem(), nil)
	return out, nil
}

// sanitizedCopy returns a deep copy of res in which every string has been
// passed through clean. All human-readable formats render from this copy, so
// no field can reach a renderer without sanitization.
func sanitizedCopy(res *model.ScanResult) (*model.ScanResult, error) {
	out, err := copyResult(res)
	if err != nil {
		return nil, err
	}
	walk(reflect.ValueOf(out).Elem(), clean)
	return out, nil
}

var timeType = reflect.TypeOf(time.Time{})

// walk visits every value reachable from v. It fills nil slices and maps and,
// when fn is not nil, rewrites every string (including map keys) with fn.
func walk(v reflect.Value, fn func(string) string) {
	switch v.Kind() {
	case reflect.String:
		if fn != nil && v.CanSet() {
			v.SetString(fn(v.String()))
		}
	case reflect.Pointer:
		if !v.IsNil() {
			walk(v.Elem(), fn)
		}
	case reflect.Struct:
		if v.Type() == timeType {
			return
		}
		for i := 0; i < v.NumField(); i++ {
			walk(v.Field(i), fn)
		}
	case reflect.Slice:
		if v.IsNil() && v.CanSet() {
			v.Set(reflect.MakeSlice(v.Type(), 0, 0))
		}
		for i := 0; i < v.Len(); i++ {
			walk(v.Index(i), fn)
		}
	case reflect.Map:
		if v.IsNil() && v.CanSet() {
			v.Set(reflect.MakeMap(v.Type()))
			return
		}
		if fn == nil || v.Type().Key().Kind() != reflect.String || !v.CanSet() {
			return
		}
		rebuilt := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			key := reflect.New(v.Type().Key()).Elem()
			key.SetString(fn(iter.Key().String()))
			val := reflect.New(v.Type().Elem()).Elem()
			val.Set(iter.Value())
			walk(val, fn)
			// When two hostile keys collapse to one, keep the larger count.
			if prev := rebuilt.MapIndex(key); prev.IsValid() && prev.CanInt() && val.CanInt() && prev.Int() > val.Int() {
				continue
			}
			rebuilt.SetMapIndex(key, val)
		}
		v.Set(rebuilt)
	}
}
