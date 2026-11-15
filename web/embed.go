// SPDX-License-Identifier: Apache-2.0

// Package web embeds the built dashboard so that "agentgov serve" works from
// a single binary. The bundle in dist/ is produced by "npm run build".
package web

import (
	"embed"
	"errors"
	"io/fs"
)

//go:embed all:dist
var bundle embed.FS

// Dist returns the built dashboard. It returns an error when the bundle
// holds no index.html, so the server can show its fallback page instead.
func Dist() (fs.FS, error) {
	sub, err := fs.Sub(bundle, "dist")
	if err != nil {
		return nil, err
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, errors.New("dashboard bundle is not built")
	}
	return sub, nil
}
