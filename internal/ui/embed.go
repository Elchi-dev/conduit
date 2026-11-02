//go:build ui

package ui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

func assets() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil
	}
	return sub
}
