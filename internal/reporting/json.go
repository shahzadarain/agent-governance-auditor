// SPDX-License-Identifier: Apache-2.0

package reporting

import (
	"bytes"
	"encoding/json"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// renderJSON writes the scan result as indented JSON with a trailing newline.
// HTML escaping stays on, so the output is safe to embed in a web page. Nil
// slices and maps are written as empty arrays and objects, which keeps the
// document valid against policies/schema/scan-result.schema.json.
func renderJSON(buf *bytes.Buffer, res *model.ScanResult) error {
	cp, err := copyResult(res)
	if err != nil {
		return err
	}
	return writeJSON(buf, cp)
}

// writeJSON encodes v with a two-space indent and a trailing newline.
func writeJSON(buf *bytes.Buffer, v any) error {
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(true)
	return enc.Encode(v)
}
