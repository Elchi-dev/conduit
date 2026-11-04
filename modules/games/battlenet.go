package games

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// battleNetProducts maps Battle.net product codes to a title and the code
// its battlenet:// launch links use.
var battleNetProducts = map[string][2]string{
	"pro":     {"Overwatch 2", "Pro"},
	"wow":     {"World of Warcraft", "WoW"},
	"d3":      {"Diablo III", "D3"},
	"fen":     {"Diablo IV", "Fen"},
	"osi":     {"Diablo II: Resurrected", "OSI"},
	"hs_beta": {"Hearthstone", "WTCG"},
	"hero":    {"Heroes of the Storm", "Hero"},
	"s1":      {"StarCraft", "S1"},
	"s2":      {"StarCraft II", "S2"},
	"w3":      {"Warcraft III: Reforged", "W3"},
	"anbs":    {"Diablo Immortal", "ANBS"},
	"odin":    {"Call of Duty: Modern Warfare", "ODIN"},
	"auks":    {"Call of Duty", "AUKS"},
	"zeus":    {"Call of Duty: Black Ops Cold War", "ZEUS"},
	"fore":    {"Call of Duty: Vanguard", "FORE"},
	"viper":   {"Call of Duty: Black Ops 4", "VIPR"},
	"rtro":    {"Blizzard Arcade Collection", "RTRO"},
	"wlby":    {"Crash Bandicoot 4", "WLBY"},
	"gryphon": {"Warcraft Rumble", "GRY"},
}

func battleNetDB(e *env) string {
	switch e.GOOS {
	case "windows":
		if e.ProgramData == "" {
			return ""
		}
		return filepath.Join(e.ProgramData, "Battle.net", "Agent", "product.db")
	case "darwin":
		return filepath.Join("/Users", "Shared", "Battle.net", "Agent", "product.db")
	}
	return ""
}

// pbField is one protobuf field: varints in Num, length-delimited in Bytes.
type pbField struct {
	Num   int
	Wire  int
	Int   uint64
	Bytes []byte
}

var errPB = errors.New("malformed protobuf")

func pbVarint(b []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7f) << (7 * i)
		if b[i] < 0x80 {
			return v, i + 1, nil
		}
	}
	return 0, 0, errPB
}

// pbDecode splits a protobuf message into its fields, without a schema.
func pbDecode(b []byte) ([]pbField, error) {
	var out []pbField
	for len(b) > 0 {
		key, n, err := pbVarint(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		f := pbField{Num: int(key >> 3), Wire: int(key & 7)}
		switch f.Wire {
		case 0:
			v, n, err := pbVarint(b)
			if err != nil {
				return nil, err
			}
			f.Int, b = v, b[n:]
		case 1:
			if len(b) < 8 {
				return nil, errPB
			}
			b = b[8:]
		case 2:
			l, n, err := pbVarint(b)
			if err != nil || uint64(len(b)-n) < l {
				return nil, errPB
			}
			f.Bytes, b = b[n:n+int(l)], b[n+int(l):]
		case 5:
			if len(b) < 4 {
				return nil, errPB
			}
			b = b[4:]
		default:
			return nil, errPB
		}
		out = append(out, f)
	}
	return out, nil
}

func pbFirst(fs []pbField, num int) *pbField {
	for i := range fs {
		if fs[i].Num == num {
			return &fs[i]
		}
	}
	return nil
}

type bnetInstall struct {
	UID, Code, Path string
	Installed       bool
}

// parseProductDB reads the installs out of Battle.net's product.db:
// Database{ repeated ProductInstall product_install = 1 }, ProductInstall{
// uid = 1, product_code = 2, settings = 3 { install_path = 1 },
// cached_product_state = 4 { base_product_state = 1 { installed = 1 } } }.
func parseProductDB(b []byte) ([]bnetInstall, error) {
	top, err := pbDecode(b)
	if err != nil {
		return nil, err
	}
	var out []bnetInstall
	for _, f := range top {
		if f.Num != 1 || f.Wire != 2 {
			continue
		}
		pi, err := pbDecode(f.Bytes)
		if err != nil {
			continue
		}
		var in bnetInstall
		if v := pbFirst(pi, 1); v != nil {
			in.UID = string(v.Bytes)
		}
		if v := pbFirst(pi, 2); v != nil {
			in.Code = string(v.Bytes)
		}
		if v := pbFirst(pi, 3); v != nil {
			if s, err := pbDecode(v.Bytes); err == nil {
				if p := pbFirst(s, 1); p != nil {
					in.Path = string(p.Bytes)
				}
			}
		}
		if v := pbFirst(pi, 4); v != nil {
			if s, err := pbDecode(v.Bytes); err == nil {
				if base := pbFirst(s, 1); base != nil {
					if bs, err := pbDecode(base.Bytes); err == nil {
						if inst := pbFirst(bs, 1); inst != nil {
							in.Installed = inst.Int == 1
						}
					}
				}
			}
		}
		out = append(out, in)
	}
	return out, nil
}

func scanBattleNet(e *env) (bool, []Game, error) {
	path := battleNetDB(e)
	b, err := os.ReadFile(path)
	if err != nil {
		return false, nil, nil // the Uninstall fallback (scanUninstall) still finds Blizzard games
	}
	ins, err := parseProductDB(b)
	if err != nil {
		return true, nil, errors.New("couldn't read Battle.net's product.db; its games show under other installed games")
	}
	var out []Game
	seen := map[string]bool{}
	for _, in := range ins {
		code := strings.ToLower(in.Code)
		if in.Path == "" || code == "" || code == "agent" || code == "bna" || code == "battle.net" || seen[code] {
			continue
		}
		seen[code] = true
		meta, ok := battleNetProducts[code]
		if !ok {
			meta = [2]string{filepath.Base(strings.ReplaceAll(in.Path, `\`, "/")), in.Code}
		}
		out = append(out, Game{
			ID: "battlenet:" + code, Title: meta[0], Launcher: "battlenet", NativeID: in.Code,
			Installed: true, InstallPath: filepath.FromSlash(in.Path),
			launch: launchSpec{URI: "battlenet://" + meta[1]},
		})
	}
	return true, out, nil
}
