package games

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// The scanners in this file read the Windows registry through env.Reg, so
// they compile everywhere and return nothing outside Windows.

var uninstallRoots = [][2]string{
	{"HKLM", `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	{"HKLM", `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
	{"HKCU", `Software\Microsoft\Windows\CurrentVersion\Uninstall`},
}

func uninstallEntries(e *env) []regKey {
	var out []regKey
	for _, r := range uninstallRoots {
		out = append(out, e.reg(r[0], r[1])...)
	}
	return out
}

// iconExe turns a DisplayIcon value (`"C:\x\game.exe",0`) into a path.
func iconExe(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, ","); i > 0 && !strings.Contains(s[i:], `\`) {
		s = s[:i]
	}
	s = strings.Trim(s, `"`)
	if !strings.HasSuffix(strings.ToLower(s), ".exe") {
		return ""
	}
	return s
}

func estimatedSize(v map[string]string) int64 {
	kb, _ := strconv.ParseInt(v["EstimatedSize"], 10, 64)
	return kb * 1024
}

var contentIDRe = regexp.MustCompile(`<contentID>\s*([^<\s]+)\s*</contentID>`)

// eaContentIDs reads the offer ids from an EA game's installer data, which
// the EA app's launch links take.
func eaContentIDs(install string) []string {
	b, err := os.ReadFile(filepath.Join(install, "__Installer", "installerdata.xml"))
	if err != nil {
		return nil
	}
	var ids []string
	for _, m := range contentIDRe.FindAllStringSubmatch(string(b), -1) {
		ids = append(ids, m[1])
	}
	return ids
}

func isEAPublisher(p string) bool {
	p = strings.ToLower(p)
	return strings.Contains(p, "electronic arts") || p == "ea" || strings.HasPrefix(p, "ea ")
}

func scanEA(e *env) (bool, []Game, error) {
	found := len(e.regValues("HKLM", `SOFTWARE\Electronic Arts\EA Desktop`)) > 0
	var out []Game
	seen := map[string]bool{}
	add := func(title, install, exe string, size int64) {
		if title == "" || install == "" {
			return
		}
		key := strings.ToLower(filepath.Clean(install))
		if seen[key] {
			return
		}
		seen[key] = true
		g := Game{ID: "ea:" + slug(title), Title: title, Launcher: "ea", NativeID: slug(title), Installed: true,
			InstallPath: install, SizeBytes: size, Size: humanSize(size)}
		if exe != "" {
			g.Executables = []string{exe}
			g.ProcessNames = baseNames(g.Executables)
		}
		if ids := eaContentIDs(install); len(ids) > 0 {
			g.NativeID = ids[0]
			g.launch = launchSpec{URI: "origin2://game/launch?offerIds=" + strings.Join(ids, ",")}
		} else if exe != "" {
			g.launch = launchSpec{Exe: exe, Dir: install}
		}
		out = append(out, g)
	}
	for _, root := range []string{`SOFTWARE\WOW6432Node\EA Games`, `SOFTWARE\WOW6432Node\Electronic Arts`} {
		for _, k := range e.reg("HKLM", root) {
			if k.Name == "EA Desktop" || k.Name == "EA Core" {
				continue
			}
			found = true
			add(firstNonEmpty(k.Values["DisplayName"], k.Name), strings.TrimRight(k.Values["Install Dir"], `\`), "", 0)
		}
	}
	for _, k := range uninstallEntries(e) {
		v := k.Values
		name := v["DisplayName"]
		if !isEAPublisher(v["Publisher"]) || v["InstallLocation"] == "" || name == "EA app" || strings.HasPrefix(name, "Origin") {
			continue
		}
		found = true
		add(name, strings.TrimRight(v["InstallLocation"], `\`), iconExe(v["DisplayIcon"]), estimatedSize(v))
	}
	return found, out, nil
}

func scanUbisoft(e *env) (bool, []Game, error) {
	found := len(e.regValues("HKLM", `SOFTWARE\WOW6432Node\Ubisoft\Launcher`)) > 0
	names := map[string]string{}
	for _, k := range uninstallEntries(e) {
		if id, ok := strings.CutPrefix(k.Name, "Uplay Install "); ok {
			names[id] = k.Values["DisplayName"]
		}
	}
	var out []Game
	for _, k := range e.reg("HKLM", `SOFTWARE\WOW6432Node\Ubisoft\Launcher\Installs`) {
		found = true
		dir := strings.TrimRight(filepath.FromSlash(k.Values["InstallDir"]), `\/`)
		if dir == "" {
			continue
		}
		title := names[k.Name]
		if title == "" {
			title = filepath.Base(strings.ReplaceAll(dir, `\`, "/"))
		}
		out = append(out, Game{ID: "ubisoft:" + k.Name, Title: title, Launcher: "ubisoft", NativeID: k.Name,
			Installed: true, InstallPath: dir, launch: launchSpec{URI: "uplay://launch/" + k.Name + "/0"}})
	}
	return found, out, nil
}

// gamePublishers are matched (lowercase, as a substring) against the
// Publisher of Windows' installed programs to find games no launcher knows.
var gamePublishers = []string{
	"blizzard", "rockstar games", "bethesda", "cd projekt", "mojang", "square enix", "bandai namco", "activision",
	"paradox interactive", "wargaming", "mihoyo", "hoyoverse", "cognosphere", "krafton", "grinding gear",
	"digital extremes", "hi-rez", "jagex", "roblox", "sega", "capcom", "2k games", "devolver", "focus entertainment",
	"warner bros. games", "netease games", "kuro games", "smilegate", "gaijin", "frontier developments",
	"larian", "innersloth", "re-logic", "nexon", "pearl abyss", "ncsoft", "riot games", "ubisoft", "epic games",
}

var notGameNames = []string{"launcher", "redistributable", "battle.net", "ea app", "ubisoft connect", "uplay",
	"riot client", "galaxy", "anti-cheat", "anticheat", "easyanticheat", "battleye", "directx", "vcredist", "uninstall", "updater"}

func scanUninstall(e *env) (bool, []Game, error) {
	var out []Game
	seen := map[string]bool{}
	ents := uninstallEntries(e)
	for _, k := range ents {
		v := k.Values
		name, pub, loc := v["DisplayName"], strings.ToLower(v["Publisher"]), strings.TrimRight(v["InstallLocation"], `\`)
		if name == "" || loc == "" || v["SystemComponent"] == "1" || strings.HasPrefix(k.Name, "Steam App ") || strings.HasPrefix(k.Name, "Uplay Install ") {
			continue
		}
		known := false
		for _, p := range gamePublishers {
			if strings.Contains(pub, p) {
				known = true
				break
			}
		}
		if !known || isEAPublisher(pub) {
			continue
		}
		low := strings.ToLower(name)
		skip := false
		for _, n := range notGameNames {
			if strings.Contains(low, n) {
				skip = true
				break
			}
		}
		if skip || seen[strings.ToLower(loc)] {
			continue
		}
		seen[strings.ToLower(loc)] = true
		launcher := "windows"
		if strings.Contains(pub, "blizzard") {
			launcher = "battlenet" // when product.db can't be read
		}
		exe := iconExe(v["DisplayIcon"])
		g := Game{ID: launcher + ":" + slug(name), Title: name, Launcher: launcher, NativeID: k.Name, Installed: true,
			InstallPath: loc, SizeBytes: estimatedSize(v), Size: humanSize(estimatedSize(v))}
		if exe != "" {
			g.Executables = []string{exe}
			g.ProcessNames = baseNames(g.Executables)
			g.launch = launchSpec{Exe: exe, Dir: loc}
		}
		out = append(out, g)
	}
	return len(ents) > 0, out, nil
}

type msGameConfig struct {
	Identity struct {
		Name string `xml:"Name,attr"`
	} `xml:"Identity"`
	StoreID     string `xml:"StoreId"`
	Executables []struct {
		Name string `xml:"Name,attr"`
		ID   string `xml:"Id,attr"`
	} `xml:"ExecutableList>Executable"`
	ShellVisuals struct {
		DefaultDisplayName string `xml:"DefaultDisplayName,attr"`
	} `xml:"ShellVisuals"`
}

// scanXbox finds games the Xbox app installed into <drive>\XboxGames, from
// each game's MicrosoftGame.config.
func scanXbox(e *env) (bool, []Game, error) {
	found := false
	var out []Game
	for _, d := range e.Drives {
		cfgs, _ := filepath.Glob(filepath.Join(d, "XboxGames", "*", "Content", "MicrosoftGame.config"))
		for _, c := range cfgs {
			found = true
			b, err := os.ReadFile(c)
			if err != nil {
				continue
			}
			var mc msGameConfig
			if xml.Unmarshal(b, &mc) != nil || mc.Identity.Name == "" {
				continue
			}
			content := filepath.Dir(c)
			root := filepath.Dir(content)
			title := mc.ShellVisuals.DefaultDisplayName
			if title == "" || strings.HasPrefix(title, "ms-resource:") {
				title = filepath.Base(root)
			}
			g := Game{ID: "xbox:" + mc.Identity.Name, Title: title, Launcher: "xbox", NativeID: mc.Identity.Name,
				Installed: true, InstallPath: root}
			for _, x := range mc.Executables {
				if x.Name != "" {
					g.Executables = append(g.Executables, filepath.Join(content, filepath.FromSlash(strings.ReplaceAll(x.Name, `\`, "/"))))
				}
			}
			g.ProcessNames = baseNames(g.Executables)
			switch {
			case mc.StoreID != "":
				g.launch = launchSpec{URI: "msxbox://game/?productId=" + mc.StoreID}
			case len(g.Executables) > 0:
				g.launch = launchSpec{Exe: g.Executables[0], Dir: content}
			}
			out = append(out, g)
		}
	}
	return found, out, nil
}
