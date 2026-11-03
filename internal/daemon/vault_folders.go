package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/elchi-dev/conduit/internal/auth"
	"github.com/elchi-dev/conduit/internal/core"
	"github.com/elchi-dev/conduit/internal/vault"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Restricted vault folders, for teams: secrets whose names start with a
// restricted folder (finance/, prod/…) can only be revealed, changed,
// deleted or used in module settings by the roles and people the folder
// names. Agents and API keys act for their owner, so they get no more than
// the person; automations only when the folder allows them. Everyone can
// still see that the secrets exist (names aren't secret).

// VaultFolder restricts one folder.
type VaultFolder struct {
	Prefix      string   `json:"prefix"` // "finance/"
	Roles       []string `json:"roles"`  // owner, admin, member, viewer
	Users       []string `json:"users"`  // user ids
	Automations bool     `json:"automations"`
}

const vaultFoldersSetting = "vault.folders"

var folderRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*/$`)

func (s *Server) vaultFolders(ctx context.Context) []VaultFolder {
	out := []VaultFolder{}
	var raw string
	if s.DB.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, vaultFoldersSetting).Scan(&raw) == nil {
		_ = json.Unmarshal([]byte(raw), &out)
	}
	return out
}

// folderFor returns the most specific restricted folder that holds name.
func folderFor(folders []VaultFolder, name string) *VaultFolder {
	var best *VaultFolder
	for i := range folders {
		if strings.HasPrefix(name, folders[i].Prefix) && (best == nil || len(folders[i].Prefix) > len(best.Prefix)) {
			best = &folders[i]
		}
	}
	return best
}

// personFor is the person an actor acts for: themselves, a key's owner.
func (s *Server) personFor(ctx context.Context, a core.Actor) (auth.User, bool) {
	switch a.Kind {
	case core.ActorUser:
		u, err := s.Auth.GetUser(ctx, a.ID)
		return u, err == nil
	case core.ActorKey, core.ActorAgent:
		k, err := s.Auth.GetKey(ctx, a.ID)
		if err != nil {
			return auth.User{}, false
		}
		u, err := s.Auth.GetUser(ctx, k.OwnerID)
		return u, err == nil
	}
	return auth.User{}, false
}

func (f VaultFolder) allows(u auth.User, ok bool) bool {
	if !ok || u.Disabled {
		return false
	}
	for _, r := range f.Roles {
		if r == string(u.Role) {
			return true
		}
	}
	for _, id := range f.Users {
		if id == u.ID {
			return true
		}
	}
	return false
}

// mayUse reports whether actor may touch secret name.
func (s *Server) mayUse(ctx context.Context, a core.Actor, name string) error {
	f := folderFor(s.vaultFolders(ctx), name)
	if f == nil || a.Kind == core.ActorSystem {
		return nil
	}
	if a.Kind == core.ActorAutomation {
		if !f.Automations {
			return fmt.Errorf("the vault folder %s is restricted and doesn't allow automations", f.Prefix)
		}
		// The folder allowing automations doesn't let anyone who can write one
		// read it: whoever saved the automation last must be allowed too.
		if s.Automations != nil {
			if au, err := s.Automations.Get(ctx, a.ID); err == nil {
				kind, id, _ := strings.Cut(au.UpdatedBy, ":")
				by := core.Actor{Kind: core.ActorKind(kind), ID: id}
				if by.Kind == core.ActorSystem {
					return nil
				}
				if u, ok := s.personFor(ctx, by); f.allows(u, ok) {
					return nil
				}
			}
		}
		return fmt.Errorf("the vault folder %s is restricted, and whoever last saved this automation may not use it", f.Prefix)
	}
	if u, ok := s.personFor(ctx, a); f.allows(u, ok) {
		return nil
	}
	return fmt.Errorf("the vault folder %s is restricted to certain people", f.Prefix)
}

// vaultGuard is the engine guard: vault actions that name a secret, or a
// folder to import into, are checked against the restricted folders.
func (s *Server) vaultGuard(ctx context.Context, a core.Actor, in core.Instance, call sdk.Call) error {
	if in.Module != "vault" {
		return nil
	}
	var p struct {
		Name   string `json:"name"`
		Prefix string `json:"prefix"`
		Text   string `json:"text"`
	}
	_ = json.Unmarshal(call.Input, &p)
	switch call.Action {
	case "reveal", "set", "delete", "totp", "rotate":
		return s.mayUse(ctx, a, strings.ToLower(strings.TrimSpace(p.Name)))
	case "import_env":
		// Check every name the import would write, exactly as the module
		// builds them.
		env, err := vault.ParseEnv(strings.NewReader(p.Text))
		if err != nil {
			return err
		}
		for k := range env {
			if err := s.mayUse(ctx, a, vault.EnvName(p.Prefix, k)); err != nil {
				return err
			}
		}
	case "import_csv":
		items, err := vault.ParseCSVExport(strings.NewReader(p.Text), p.Prefix)
		if err != nil {
			return nil // the module reports the bad file
		}
		for _, it := range items {
			if err := s.mayUse(ctx, a, it.Name); err != nil {
				return err
			}
		}
	case "scan_text", "scan_path":
		// A scan compares text with every secret's value, so it would tell
		// whether a guess matches a restricted one.
		for _, f := range s.vaultFolders(ctx) {
			if err := s.mayUse(ctx, a, f.Prefix); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkConfigRefs refuses module settings that use secrets from a folder
// the person saving them may not use (a module could otherwise send the
// secret anywhere).
func (s *Server) checkConfigRefs(r *http.Request, cfg json.RawMessage) error {
	p, _ := principal(r)
	// Walk the decoded settings, as the engine does when it resolves them:
	// a regex over the raw JSON misses escaped forms like secret:\/\/x.
	for ref := range core.ConfigRefs(cfg) {
		if err := s.mayUse(r.Context(), p.Actor, strings.TrimPrefix(ref, "secret://")); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) vaultFolderRoutes() []route {
	return []route{
		{"GET /api/v1/vault/folders", s.need("modules:*:read", s.getVaultFolders)},
		{"PUT /api/v1/vault/folders", s.need("admin:*:*", s.putVaultFolders)},
	}
}

func (s *Server) getVaultFolders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.vaultFolders(r.Context()))
}

// putVaultFolders is for the owner only: restrictions apply to admins too,
// so an admin mustn't be able to lift one.
func (s *Server) putVaultFolders(w http.ResponseWriter, r *http.Request) {
	if !s.humanOnly(w, r) {
		return
	}
	p, _ := principal(r)
	if p.User.Role != auth.RoleOwner {
		writeErr(w, http.StatusForbidden, "only the owner can restrict vault folders")
		return
	}
	var fs []VaultFolder
	if err := readJSON(r, &fs); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	seen := map[string]bool{}
	for i := range fs {
		f := &fs[i]
		f.Prefix = strings.ToLower(strings.TrimSpace(f.Prefix))
		if !strings.HasSuffix(f.Prefix, "/") {
			f.Prefix += "/"
		}
		if !folderRe.MatchString(f.Prefix) || seen[f.Prefix] {
			writeErr(w, http.StatusBadRequest, "folders look like finance/ or prod/db/, each once")
			return
		}
		seen[f.Prefix] = true
		for _, role := range f.Roles {
			switch auth.Role(role) {
			case auth.RoleOwner, auth.RoleAdmin, auth.RoleMember, auth.RoleViewer:
			default:
				writeErr(w, http.StatusBadRequest, "roles are owner, admin, member and viewer")
				return
			}
		}
		// The owner always keeps access, so a folder can't lock everyone out.
		has := false
		for _, role := range f.Roles {
			has = has || role == string(auth.RoleOwner)
		}
		if !has {
			f.Roles = append(f.Roles, string(auth.RoleOwner))
		}
		if f.Users == nil {
			f.Users = []string{}
		}
	}
	if len(fs) > 100 {
		writeErr(w, http.StatusBadRequest, "at most 100 restricted folders")
		return
	}
	b, _ := json.Marshal(fs)
	if _, err := s.DB.ExecContext(r.Context(), `INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, vaultFoldersSetting, string(b)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auditConfig(r, "vault_folders_changed", "vault", fs)
	writeJSON(w, http.StatusOK, fs)
}

func principalActor(r *http.Request) core.Actor {
	p, _ := principal(r)
	return p.Actor
}
