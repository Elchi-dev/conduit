package games

import (
	"context"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

// proc is a running process as the matcher sees it.
type proc struct {
	PID     int32     `json:"pid"`
	Name    string    `json:"name"`
	Exe     string    `json:"exe,omitempty"`
	Cmdline []string  `json:"-"`
	Started time.Time `json:"-"`
}

// listProcs lists running processes with gopsutil, which needs no cgo on
// Linux, Windows and macOS. On Linux it also reads command lines, which is
// how games under Wine and Proton are recognised.
func listProcs(ctx context.Context) ([]proc, error) {
	ps, err := process.ProcessesWithContext(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]proc, 0, len(ps))
	for _, p := range ps {
		exe, _ := p.ExeWithContext(ctx)
		name, _ := p.NameWithContext(ctx)
		if exe == "" && name == "" {
			continue
		}
		pr := proc{PID: p.Pid, Name: name, Exe: exe}
		if runtime.GOOS == "linux" {
			pr.Cmdline, _ = p.CmdlineSliceWithContext(ctx)
		}
		if ct, err := p.CreateTimeWithContext(ctx); err == nil && ct > 0 {
			pr.Started = time.UnixMilli(ct)
		}
		out = append(out, pr)
	}
	return out, nil
}

// normPath makes paths comparable: forward slashes, no trailing slash,
// lowercase where file systems usually ignore case. A Wine path (Z:\home\…)
// on Linux becomes the Unix path it stands for.
func normPath(p, goos string) string {
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, `\`, "/")
	if goos == "linux" && len(p) > 2 && p[1] == ':' && p[2] == '/' {
		if p[0] != 'Z' && p[0] != 'z' {
			return "" // another Wine drive: can't map it
		}
		p = p[2:]
	}
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = strings.TrimSuffix(p, "/")
	}
	if goos != "linux" {
		p = strings.ToLower(p)
	}
	return p
}

// broadPaths are install folders too general to say a process is a game.
var broadPaths = map[string]bool{
	"/usr": true, "/usr/bin": true, "/usr/local": true, "/usr/local/bin": true, "/opt": true, "/bin": true, "/applications": true,
	"/Applications": true, "c:/program files": true, "c:/program files (x86)": true, "c:/windows": true, "c:/games": true,
}

func tooBroad(p, home string) bool {
	if p == "" || broadPaths[p] || (home != "" && strings.EqualFold(p, home)) {
		return true
	}
	segs := 0
	for _, s := range strings.Split(p, "/") {
		if s != "" && !strings.HasSuffix(s, ":") {
			segs++
		}
	}
	return segs < 2
}

var steamAppIDRe = regexp.MustCompile(`^AppId=(\d+)$`)

// matchProcs assigns running processes to games: a process belongs to the
// game whose install folder holds its executable (the deepest one wins), or
// whose executable list names it exactly (or, when the path is hidden, by
// the program name the launcher lists). On Linux, Wine and Proton
// processes are matched through the Windows paths in their command line,
// and Steam's launch wrapper through its AppId= argument. Games that give
// process names (custom games) also match by name.
func matchProcs(procs []proc, games []Game, goos, home string) map[string][]proc {
	type root struct {
		path string
		id   string
	}
	var roots []root
	exact := map[string]string{}
	names := map[string]string{}
	// Launcher-listed program names count only when a process's path can't
	// be read (Windows hides it for anti-cheat protected games).
	hidden := map[string]string{}
	steamIDs := map[string]string{}
	for _, g := range games {
		if !g.Installed {
			continue
		}
		if p := normPath(g.InstallPath, goos); !tooBroad(p, normPath(home, goos)) {
			roots = append(roots, root{p, g.ID})
		}
		for _, x := range g.Executables {
			if p := normPath(x, goos); p != "" {
				exact[p] = g.ID
			}
		}
		for _, n := range g.ProcessNames {
			if g.Custom {
				names[strings.ToLower(n)] = g.ID
			} else if _, taken := hidden[strings.ToLower(n)]; !taken {
				hidden[strings.ToLower(n)] = g.ID
			}
		}
		if g.Launcher == "steam" {
			steamIDs[g.NativeID] = g.ID
		}
	}
	sort.Slice(roots, func(i, j int) bool { return len(roots[i].path) > len(roots[j].path) })
	find := func(p string) string {
		p = normPath(p, goos)
		if p == "" {
			return ""
		}
		if id, ok := exact[p]; ok {
			return id
		}
		for _, r := range roots {
			if strings.HasPrefix(p, r.path+"/") {
				return r.id
			}
		}
		return ""
	}
	out := map[string][]proc{}
	for _, pr := range procs {
		id := find(pr.Exe)
		if id == "" && goos == "linux" {
			for _, a := range pr.Cmdline {
				if m := steamAppIDRe.FindStringSubmatch(a); m != nil {
					if sid, ok := steamIDs[m[1]]; ok {
						id = sid
						break
					}
				}
				if strings.HasPrefix(a, "/") || (len(a) > 2 && a[1] == ':') {
					if id = find(a); id != "" {
						break
					}
				}
			}
		}
		if id == "" {
			n := strings.ToLower(pr.Name)
			if n == "" && pr.Exe != "" {
				n = strings.ToLower(filepath.Base(strings.ReplaceAll(pr.Exe, `\`, "/")))
			}
			id = names[n]
			if id == "" && pr.Exe == "" {
				id = hidden[n]
			}
		}
		if id != "" {
			out[id] = append(out[id], pr)
		}
	}
	for id := range out {
		sort.Slice(out[id], func(i, j int) bool { return out[id][i].PID < out[id][j].PID })
	}
	return out
}

func pidExists(pid int32) bool {
	ok, err := process.PidExists(pid)
	return err == nil && ok
}
