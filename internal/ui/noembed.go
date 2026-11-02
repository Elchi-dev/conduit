//go:build !ui

package ui

import "io/fs"

func assets() fs.FS { return nil }
