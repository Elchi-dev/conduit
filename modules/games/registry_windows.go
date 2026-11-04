//go:build windows

package games

import (
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func rootKey(root string) (registry.Key, bool) {
	switch strings.ToUpper(root) {
	case "HKLM":
		return registry.LOCAL_MACHINE, true
	case "HKCU":
		return registry.CURRENT_USER, true
	}
	return 0, false
}

// regSubkeys lists the subkeys of root\path with their values.
func regSubkeys(root, path string) []regKey {
	rk, ok := rootKey(root)
	if !ok {
		return nil
	}
	k, err := registry.OpenKey(rk, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	out := make([]regKey, 0, len(names))
	for _, n := range names {
		out = append(out, regKey{Name: n, Values: regValues(root, path+`\`+n)})
	}
	return out
}

// regValues reads the string and integer values of root\path.
func regValues(root, path string) map[string]string {
	rk, ok := rootKey(root)
	if !ok {
		return nil
	}
	k, err := registry.OpenKey(rk, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, err := k.ReadValueNames(-1)
	if err != nil {
		return nil
	}
	vals := map[string]string{}
	for _, n := range names {
		if s, _, err := k.GetStringValue(n); err == nil {
			vals[n] = s
		} else if i, _, err := k.GetIntegerValue(n); err == nil {
			vals[n] = strconv.FormatUint(i, 10)
		}
	}
	return vals
}
