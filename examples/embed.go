// SPDX-License-Identifier: Apache-2.0

// Package examples embeds the safe reference agent so the CLI can write it
// out as a starter project.
package examples

import "embed"

// SafeAgent holds the files of examples/safe-agent, rooted at "safe-agent".
// It includes dot-files such as .agentgov.yaml and the CI workflow fixture.
//
//go:embed all:safe-agent
var SafeAgent embed.FS
