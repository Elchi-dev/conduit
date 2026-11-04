package daemon

import "path/filepath"

// dataSub is a folder inside the data folder, or "" when there is none (the
// module then reports itself unconfigured).
func (a *App) dataSub(name string) string {
	if a.DataDir == "" {
		return ""
	}
	return filepath.Join(a.DataDir, name)
}
