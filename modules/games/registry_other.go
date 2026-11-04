//go:build !windows

package games

// There is no registry outside Windows.
func regSubkeys(string, string) []regKey { return nil }

func regValues(string, string) map[string]string { return nil }
