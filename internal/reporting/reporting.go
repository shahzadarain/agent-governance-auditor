// SPDX-License-Identifier: Apache-2.0

// Package reporting renders a model.ScanResult as terminal text, JSON,
// Markdown, a self-contained HTML page, or SARIF 2.1.0, and compares two scan
// results.
//
// Every format renders from the same ScanResult. Repository-derived strings
// are treated as untrusted: control characters and terminal escape sequences
// are removed before any human-readable format is produced, and each format
// then applies its own escaping.
package reporting

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/shahzadarain/agent-governance-auditor/internal/model"
)

// Format names accepted by Render.
const (
	FormatTerminal = "terminal"
	FormatJSON     = "json"
	FormatMarkdown = "markdown"
	FormatHTML     = "html"
	FormatSARIF    = "sarif"
)

// DefaultWidth is the terminal wrap width used when Options.Width is not set.
const DefaultWidth = 100

// Options controls rendering. The zero value is valid.
type Options struct {
	Color       bool // emit ANSI colors in terminal output; the caller decides (TTY, NO_COLOR)
	Full        bool // include the full control matrix in terminal output
	SummaryOnly bool // terminal output: header, score, decision, and reasons only
	Width       int  // terminal wrap width; 0 means DefaultWidth

	// InformationURI is written to the SARIF tool.driver.informationUri
	// property. It is left out when empty.
	InformationURI string
}

// Formats returns the format names accepted by Render.
func Formats() []string {
	return []string{FormatTerminal, FormatJSON, FormatMarkdown, FormatHTML, FormatSARIF}
}

// ComparisonFormats returns the format names accepted by RenderComparison.
func ComparisonFormats() []string {
	return []string{FormatTerminal, FormatJSON, FormatMarkdown}
}

// Render writes res to w in the given format. Output is deterministic for a
// given result and options. Nothing is written when rendering fails.
func Render(w io.Writer, res *model.ScanResult, format string, opts Options) error {
	if res == nil {
		return errors.New("reporting: scan result is nil")
	}
	var buf bytes.Buffer
	var err error
	switch format {
	case FormatTerminal:
		err = renderTerminal(&buf, res, opts)
	case FormatJSON:
		err = renderJSON(&buf, res)
	case FormatMarkdown:
		err = renderMarkdown(&buf, res)
	case FormatHTML:
		err = renderHTML(&buf, res)
	case FormatSARIF:
		err = renderSARIF(&buf, res, opts)
	default:
		return unknownFormat(format, Formats())
	}
	if err != nil {
		return fmt.Errorf("reporting: render %s: %w", format, err)
	}
	_, err = w.Write(buf.Bytes())
	return err
}

func unknownFormat(format string, valid []string) error {
	return fmt.Errorf("reporting: unknown format %q; valid formats are: %s",
		clean(format), strings.Join(valid, ", "))
}
