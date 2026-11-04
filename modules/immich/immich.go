// Package immich reads an Immich photo server through an API key: version,
// statistics, storage, users, jobs, recent assets and albums. It can start
// one of Immich's background jobs.
package immich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Immich server.
type Config struct {
	URL    string `json:"url"`    // e.g. https://photos.example.com
	APIKey string `json:"apiKey"` // secret:// API key
}

type conn struct{ api *rest.Client }

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
}

// New returns the Immich module.
func New() *Module { return &Module{} }

// jobs are the queues an administrator can start from Immich's Jobs page.
var jobs = []string{"thumbnailGeneration", "metadataExtraction", "videoConversion", "faceDetection", "facialRecognition",
	"smartSearch", "duplicateDetection", "library", "sidecar", "storageTemplateMigration", "migration", "backupDatabase"}

func knownJob(s string) bool {
	for _, j := range jobs {
		if j == s {
			return true
		}
	}
	return false
}

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	enum, _ := json.Marshal(jobs)
	return sdk.Manifest{
		ID: "immich", Name: "Immich", Version: "0.1.0", Category: "Media", Icon: "photo",
		Description: "Your Immich photo server: library size, storage, users, background jobs, recent uploads and albums.",
		Presets:     []string{"homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["url","apiKey"],"properties":{
			"url":{"type":"string","description":"The server's address, e.g. https://photos.example.com"},
			"apiKey":{"type":"string","x-secret":true,"description":"API key (Account settings, API keys). An administrator's key also reads statistics, users and jobs"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "server", Title: "Server", Description: "Version and how many photos and videos, using how much space (statistics need an admin key).", Risk: sdk.RiskRead},
			{Name: "storage", Title: "Storage", Description: "Disk size, used and free space of the library volume.", Risk: sdk.RiskRead},
			{Name: "users", Title: "Users", Description: "How many users and admins, with each user's photos, videos and usage (admin key).", Risk: sdk.RiskRead},
			{Name: "jobs", Title: "Jobs", Description: "Each background job queue: active, waiting, failed, paused.", Risk: sdk.RiskRead},
			{Name: "start_job", Title: "Start a job", Description: "Starts a background job for the assets that need it. Running it for every asset is start_job_force.", Risk: sdk.RiskWrite, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["job"],"properties":{"job":{"type":"string","enum":` + string(enum) + `}}}`)},
			{Name: "start_job_force", Title: "Start a job for every asset", Description: "Starts a background job for every asset, redoing existing results; for face detection and recognition that discards the existing faces and people (names, merges) and rebuilds them.", Risk: sdk.RiskDestructive, DryRun: true,
				Input: sdk.Schema(`{"type":"object","required":["job"],"properties":{"job":{"type":"string","enum":` + string(enum) + `}}}`)},
			{Name: "recent_assets", Title: "Recent uploads", Description: "Newest photos and videos: file name, type, date taken, camera and place (no image data).", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","properties":{"limit":{"type":"integer","default":25,"maximum":100}}}`)},
			{Name: "albums", Title: "Albums", Description: "Albums with their size, owner and whether they're shared.", Risk: sdk.RiskRead},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(c.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("the address is like https://photos.example.com")
	}
	if !strings.HasPrefix(c.APIKey, "secret://") {
		return errors.New("store the API key in the vault and enter its secret:// reference")
	}
	key := c.APIKey
	base := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/api") + "/api"
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		k, err := h.Secret(ctx, key)
		if err != nil {
			return err
		}
		r.Header.Set("x-api-key", strings.TrimSpace(k))
		return nil
	})
	if m.HTTP != nil {
		api.HTTP = m.HTTP
	} else {
		api.HTTP = sdk.HTTPClient(h, 30*time.Second) // through the instance's network, if any
	}
	// The key travels in x-api-key, which Go would forward to another host.
	api.HTTP = rest.SameHostOnly(api.HTTP)
	m.set.Put(id, &conn{api: api})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var me struct {
		Name    string `json:"name"`
		IsAdmin bool   `json:"isAdmin"`
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/users/me", nil, nil, &me); err != nil {
		if rest.IsStatus(err, http.StatusUnauthorized) {
			return sdk.Health{Status: "down", Message: "Immich refused the API key"}
		}
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	msg := "signed in as " + me.Name
	if me.IsAdmin {
		msg += " (admin)"
	}
	if v := c.version(ctx); v != "" {
		msg += " · Immich " + v
	}
	return sdk.Health{Status: "ok", Message: msg}
}

func (c *conn) version(ctx context.Context) string {
	var v struct {
		Major, Minor, Patch int
	}
	if _, err := c.api.Do(ctx, http.MethodGet, "/server/version", nil, nil, &v); err != nil || v.Major+v.Minor+v.Patch == 0 {
		return ""
	}
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}

type stats struct {
	Photos      int   `json:"photos"`
	Videos      int   `json:"videos"`
	Usage       int64 `json:"usage"`
	UsageByUser []struct {
		UserID   string `json:"userId"`
		UserName string `json:"userName"`
		Photos   int    `json:"photos"`
		Videos   int    `json:"videos"`
		Usage    int64  `json:"usage"`
		Quota    *int64 `json:"quotaSizeInBytes"`
	} `json:"usageByUser"`
}

func adminOnly(err error) error {
	if rest.IsStatus(err, http.StatusForbidden) {
		return errors.New("this needs an administrator's API key")
	}
	return err
}

func gb(n int64) float64 { return float64(n*100/1e9) / 100 }

type jobQueue struct {
	JobCounts struct {
		Active    int `json:"active"`
		Completed int `json:"completed"`
		Failed    int `json:"failed"`
		Delayed   int `json:"delayed"`
		Waiting   int `json:"waiting"`
		Paused    int `json:"paused"`
	} `json:"jobCounts"`
	QueueStatus struct {
		IsActive bool `json:"isActive"`
		IsPaused bool `json:"isPaused"`
	} `json:"queueStatus"`
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Job   string `json:"job"`
		Force bool   `json:"force"`
		Limit int    `json:"limit"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "server":
		out := map[string]any{"version": c.version(ctx)}
		var s stats
		if _, err := c.api.Do(ctx, http.MethodGet, "/server/statistics", nil, nil, &s); err != nil {
			if !rest.IsStatus(err, http.StatusForbidden) {
				return sdk.Result{}, err
			}
			out["statistics"] = "needs an administrator's API key"
		} else {
			out["photos"], out["videos"], out["usageGB"] = s.Photos, s.Videos, gb(s.Usage)
		}
		return sdk.JSON(out)

	case "storage":
		var s struct {
			DiskSize            string  `json:"diskSize"`
			DiskUse             string  `json:"diskUse"`
			DiskAvailable       string  `json:"diskAvailable"`
			DiskUsagePercentage float64 `json:"diskUsagePercentage"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/server/storage", nil, nil, &s); err != nil {
			return sdk.Result{}, err
		}
		return sdk.JSON(map[string]any{"size": s.DiskSize, "used": s.DiskUse, "available": s.DiskAvailable, "usedPercent": s.DiskUsagePercentage})

	case "users":
		var users []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			IsAdmin   bool   `json:"isAdmin"`
			Status    string `json:"status"`
			DeletedAt string `json:"deletedAt"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/admin/users", nil, nil, &users); err != nil {
			return sdk.Result{}, adminOnly(err)
		}
		var s stats
		if _, err := c.api.Do(ctx, http.MethodGet, "/server/statistics", nil, nil, &s); err != nil {
			return sdk.Result{}, adminOnly(err)
		}
		usage := map[string]int{}
		for i, u := range s.UsageByUser {
			usage[u.UserID] = i
		}
		admins, active := 0, 0
		rows := []map[string]any{}
		for _, u := range users {
			if u.IsAdmin {
				admins++
			}
			if u.DeletedAt == "" && (u.Status == "" || u.Status == "active") {
				active++
			}
			row := map[string]any{"name": u.Name, "admin": u.IsAdmin}
			if u.Status != "" {
				row["status"] = u.Status
			}
			if i, ok := usage[u.ID]; ok {
				x := s.UsageByUser[i]
				row["photos"], row["videos"], row["usageGB"] = x.Photos, x.Videos, gb(x.Usage)
				if x.Quota != nil {
					row["quotaGB"] = gb(*x.Quota)
				}
			}
			rows = append(rows, row)
		}
		return sdk.JSON(map[string]any{"total": len(users), "admins": admins, "active": active, "users": rows})

	case "jobs":
		all, err := c.jobs(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		names := make([]string, 0, len(all))
		for n := range all {
			names = append(names, n)
		}
		sort.Strings(names)
		out := []map[string]any{}
		for _, n := range names {
			q := all[n]
			out = append(out, map[string]any{"job": n, "running": q.QueueStatus.IsActive, "paused": q.QueueStatus.IsPaused,
				"active": q.JobCounts.Active, "waiting": q.JobCounts.Waiting, "delayed": q.JobCounts.Delayed, "failed": q.JobCounts.Failed})
		}
		return sdk.JSON(out)

	case "start_job", "start_job_force":
		if !knownJob(p.Job) {
			return sdk.Result{}, fmt.Errorf("the job is one of %s", strings.Join(jobs, ", "))
		}
		// force redoes every asset and, for faces, wipes the people already
		// recognised and named: only the destructive start_job_force does it.
		if call.Action == "start_job" && p.Force {
			return sdk.Result{}, errors.New("start_job runs for the assets that need it; running it for every asset is start_job_force (destructive)")
		}
		p.Force = call.Action == "start_job_force"
		scope := "assets that need it"
		if p.Force {
			scope = "every asset"
			if p.Job == "faceDetection" || p.Job == "facialRecognition" {
				scope += ", discarding the existing faces and people"
			}
		}
		if call.DryRun {
			all, err := c.jobs(ctx)
			if err != nil {
				return sdk.Result{}, err
			}
			before, _ := json.Marshal(all[p.Job])
			after, _ := json.Marshal(map[string]any{"command": "start", "force": p.Force})
			return sdk.Result{Plan: &sdk.Plan{Summary: fmt.Sprintf("Start the %s job for %s", p.Job, scope),
				Changes: []sdk.Change{{Target: "job " + p.Job, Op: "start", Before: before, After: after}}}}, nil
		}
		var q jobQueue
		if _, err := c.api.Do(ctx, http.MethodPut, "/jobs/"+p.Job, nil, map[string]any{"command": "start", "force": p.Force}, &q); err != nil {
			if rest.IsStatus(err, http.StatusBadRequest) {
				return sdk.Result{}, fmt.Errorf("the server didn't start %s (it may be running already): %v", p.Job, err)
			}
			return sdk.Result{}, adminOnly(err)
		}
		return sdk.JSON(map[string]any{"started": p.Job, "for": scope, "waiting": q.JobCounts.Waiting, "active": q.JobCounts.Active})

	case "recent_assets":
		limit := p.Limit
		if limit <= 0 || limit > 100 {
			limit = 25
		}
		var r struct {
			Assets struct {
				Total int `json:"total"`
				Items []struct {
					ID               string `json:"id"`
					Type             string `json:"type"`
					OriginalFileName string `json:"originalFileName"`
					FileCreatedAt    string `json:"fileCreatedAt"`
					LocalDateTime    string `json:"localDateTime"`
					IsFavorite       bool   `json:"isFavorite"`
					IsArchived       bool   `json:"isArchived"`
					Visibility       string `json:"visibility"`
					Duration         string `json:"duration"`
					Owner            *struct {
						Name string `json:"name"`
					} `json:"owner"`
					ExifInfo *struct {
						Make     string `json:"make"`
						Model    string `json:"model"`
						City     string `json:"city"`
						Country  string `json:"country"`
						FileSize int64  `json:"fileSizeInByte"`
					} `json:"exifInfo"`
				} `json:"items"`
			} `json:"assets"`
		}
		body := map[string]any{"size": limit, "order": "desc", "withExif": true}
		if _, err := c.api.Do(ctx, http.MethodPost, "/search/metadata", nil, body, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, a := range r.Assets.Items {
			row := map[string]any{"id": a.ID, "type": strings.ToLower(a.Type), "file": a.OriginalFileName, "taken": a.LocalDateTime, "created": a.FileCreatedAt}
			if a.IsFavorite {
				row["favorite"] = true
			}
			if a.IsArchived || a.Visibility == "archive" {
				row["archived"] = true
			}
			if a.Type == "VIDEO" && a.Duration != "" {
				row["duration"] = a.Duration
			}
			if a.Owner != nil {
				row["owner"] = a.Owner.Name
			}
			if e := a.ExifInfo; e != nil {
				if cam := strings.TrimSpace(e.Make + " " + e.Model); cam != "" {
					row["camera"] = cam
				}
				if place := strings.Trim(e.City+", "+e.Country, ", "); place != "" {
					row["place"] = place
				}
				if e.FileSize > 0 {
					row["sizeMB"] = float64(e.FileSize*10/1e6) / 10
				}
			}
			out = append(out, row)
		}
		return sdk.JSON(map[string]any{"total": r.Assets.Total, "assets": out})

	case "albums":
		var list []struct {
			ID         string `json:"id"`
			AlbumName  string `json:"albumName"`
			AssetCount int    `json:"assetCount"`
			Shared     bool   `json:"shared"`
			UpdatedAt  string `json:"updatedAt"`
			StartDate  string `json:"startDate"`
			EndDate    string `json:"endDate"`
			Owner      struct {
				Name string `json:"name"`
			} `json:"owner"`
		}
		if _, err := c.api.Do(ctx, http.MethodGet, "/albums", nil, nil, &list); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]any{}
		for _, a := range list {
			out = append(out, map[string]any{"id": a.ID, "name": a.AlbumName, "assets": a.AssetCount, "shared": a.Shared, "owner": a.Owner.Name, "from": a.StartDate, "to": a.EndDate, "updated": a.UpdatedAt})
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

func (c *conn) jobs(ctx context.Context) (map[string]jobQueue, error) {
	var all map[string]jobQueue
	if _, err := c.api.Do(ctx, http.MethodGet, "/jobs", nil, nil, &all); err != nil {
		return nil, adminOnly(err)
	}
	return all, nil
}
