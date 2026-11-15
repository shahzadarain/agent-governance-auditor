// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import "os"

// enableVirtualTerminal is a no-op outside Windows.
func enableVirtualTerminal(_ *os.File) bool { return true }
