// Package scaleway manages Scaleway Instances, lists Kubernetes Kapsule
// clusters and Object Storage buckets, through the Scaleway API and its S3
// endpoint.
package scaleway

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/aws"
	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one Scaleway project (or organization) in one zone.
type Config struct {
	SecretKey string `json:"secretKey"` // secret:// API key's secret key
	AccessKey string `json:"accessKey"` // the API key's access key, for Object Storage
	ProjectID string `json:"projectId"` // only this project's resources
	Zone      string `json:"zone"`      // default fr-par-1
}

type conn struct {
	api       *rest.Client
	http      *http.Client
	host      sdk.Host
	secret    string // reference
	accessKey string
	project   string
	zone      string
	region    string
	s3        string // Object Storage endpoint
	now       func() time.Time
}

// Module implements sdk.Module.
type Module struct {
	set inst.Set[conn]
	// HTTP replaces the client made from the host (tests).
	HTTP *http.Client
	// Base replaces https://api.scaleway.com (tests).
	Base string
	// S3Base replaces https://s3.<region>.scw.cloud (tests).
	S3Base string
	// Now replaces time.Now when signing Object Storage requests (tests).
	Now func() time.Time
}

// New returns the Scaleway module.
func New() *Module { return &Module{} }

const defaultBase = "https://api.scaleway.com"

var (
	uuidRe   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	zoneRe   = regexp.MustCompile(`^[a-z]{2}-[a-z]{3}-[1-9]$`)
	accessRe = regexp.MustCompile(`^SCW[A-Z0-9]{17}$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	one := sdk.Schema(`{"type":"object","required":["server"],"properties":{"server":{"type":"string","description":"Server id (from Servers)"}}}`)
	return sdk.Manifest{
		ID: "scaleway", Name: "Scaleway", Version: "0.1.0", Category: "Infrastructure", Icon: "cloud",
		Description: "Your Scaleway Instances in one zone: state, type and addresses, power on, power off and reboot; Kubernetes Kapsule clusters and Object Storage buckets.",
		Presets:     []string{"developer", "homelab"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["secretKey"],"properties":{
			"secretKey":{"type":"string","x-secret":true,"description":"An API key's secret key (IAM, API keys). InstancesReadOnly and KubernetesReadOnly to watch; InstancesFullAccess to power servers; ObjectStorageReadOnly for buckets"},
			"accessKey":{"type":"string","description":"The same API key's access key (SCW…), needed only for Object Storage buckets"},
			"projectId":{"type":"string","description":"Only this project's resources (its id); all the key can see when empty"},
			"zone":{"type":"string","default":"fr-par-1","description":"Availability zone for Instances, e.g. fr-par-1, nl-ams-1, pl-waw-1. Kapsule and Object Storage use its region"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "servers", Title: "Servers", Description: "Instances in the zone with state, commercial type, addresses and tags.", Risk: sdk.RiskRead},
			{Name: "clusters", Title: "Kapsule clusters", Description: "Kubernetes Kapsule clusters in the region: status, version, type and whether an upgrade is available. Never kubeconfigs or credentials.", Risk: sdk.RiskRead},
			{Name: "buckets", Title: "Object Storage buckets", Description: "Buckets in the region and when they were created (needs the access key).", Risk: sdk.RiskRead},
			{Name: "power_on", Title: "Power on", Description: "Starts a server that is stopped in place (still on its hypervisor and still billed). A fully stopped server needs power_on_billable.", Risk: sdk.RiskWrite, DryRun: true, Input: one},
			{Name: "power_on_billable", Title: "Power on (billing resumes)", Description: "Starts a fully stopped server: Scaleway allocates it a hypervisor again and bills its commercial type by the hour from then on (destructive). The preview shows the type. Undo powers it off again.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: one},
			{Name: "power_off", Title: "Power off", Description: "Stops a server and releases it from its hypervisor: its services go down until it's powered on, and an address that isn't a flexible IP may change (destructive). Undo powers it on.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: one},
			{Name: "reboot", Title: "Reboot", Description: "Reboots a running server; its services go down while it restarts (destructive).", Risk: sdk.RiskDestructive, DryRun: true, Input: one},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if !strings.HasPrefix(c.SecretKey, "secret://") {
		return errors.New("store the secret key in the vault and enter its secret:// reference")
	}
	c.AccessKey = strings.TrimSpace(c.AccessKey)
	if strings.HasPrefix(c.AccessKey, "secret://") {
		return errors.New("the access key isn't secret: enter it as it is (SCW…); the secret key goes in the vault")
	}
	if c.AccessKey != "" && !accessRe.MatchString(c.AccessKey) {
		return errors.New("the access key looks like SCW followed by 17 letters and digits")
	}
	c.ProjectID = strings.ToLower(strings.TrimSpace(c.ProjectID))
	if c.ProjectID != "" && !uuidRe.MatchString(c.ProjectID) {
		return errors.New("the project id is a UUID (Project settings)")
	}
	if c.Zone == "" {
		c.Zone = "fr-par-1"
	}
	if !zoneRe.MatchString(c.Zone) {
		return errors.New("the zone looks like fr-par-1, nl-ams-1 or pl-waw-1")
	}
	region := c.Zone[:len(c.Zone)-2]
	base := defaultBase
	if m.Base != "" {
		base = m.Base
	}
	s3 := "https://s3." + region + ".scw.cloud"
	if m.S3Base != "" {
		s3 = strings.TrimRight(m.S3Base, "/")
	}
	ref := c.SecretKey
	api := rest.New(base, func(ctx context.Context, r *http.Request) error {
		t, err := h.Secret(ctx, ref)
		if err != nil {
			return err
		}
		r.Header.Set("X-Auth-Token", strings.TrimSpace(t))
		return nil
	})
	client := m.HTTP
	if client == nil {
		client = sdk.HTTPClient(h, 30*time.Second)
	}
	// The key travels in X-Auth-Token, which Go forwards on any redirect.
	api.HTTP = rest.SameHostOnly(client)
	now := m.Now
	if now == nil {
		now = time.Now
	}
	m.set.Put(id, &conn{api: api, http: api.HTTP, host: h, secret: ref, accessKey: c.AccessKey, project: c.ProjectID, zone: c.Zone, region: region, s3: s3, now: now})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func friendly(err error, what string) error {
	switch {
	case rest.IsStatus(err, http.StatusUnauthorized):
		return errors.New("Scaleway refused the secret key")
	case rest.IsStatus(err, http.StatusForbidden):
		return errors.New("Scaleway refused: the API key's policy doesn't allow this")
	case rest.IsStatus(err, http.StatusNotFound):
		return fmt.Errorf("there's no %s", what)
	case rest.IsStatus(err, http.StatusTooManyRequests):
		return errors.New("Scaleway's rate limit was hit; try again in a moment")
	}
	return err
}

type server struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	State    string `json:"state"`
	Type     string `json:"commercial_type"`
	Arch     string `json:"arch"`
	PublicIP *struct {
		Address string `json:"address"`
	} `json:"public_ip"`
	PublicIPs []struct {
		Address string `json:"address"`
	} `json:"public_ips"`
	PrivateIP *string  `json:"private_ip"`
	Zone      string   `json:"zone"`
	Tags      []string `json:"tags"`
	Created   string   `json:"creation_date"`
	Project   string   `json:"project"`
}

func (c *conn) zonePath() string { return "/instance/v1/zones/" + c.zone }

func (c *conn) servers(ctx context.Context) ([]server, error) {
	var out []server
	for page := 1; page <= 20; page++ {
		q := url.Values{"page": {strconv.Itoa(page)}, "per_page": {"100"}}
		if c.project != "" {
			q.Set("project", c.project)
		}
		var r struct {
			Servers []server `json:"servers"`
		}
		hdr, err := c.api.Do(ctx, http.MethodGet, c.zonePath()+"/servers", q, nil, &r)
		if err != nil {
			return nil, friendly(err, "server list")
		}
		out = append(out, r.Servers...)
		total, _ := strconv.Atoi(hdr.Get("X-Total-Count"))
		if len(r.Servers) < 100 || len(out) >= total {
			break
		}
	}
	return out, nil
}

func (c *conn) server(ctx context.Context, id string) (server, error) {
	var r struct {
		Server server `json:"server"`
	}
	_, err := c.api.Do(ctx, http.MethodGet, c.zonePath()+"/servers/"+id, nil, nil, &r)
	if err == nil && c.project != "" && r.Server.Project != c.project {
		return server{}, errors.New("there's no such server in this project")
	}
	return r.Server, friendly(err, "such server in "+c.zone)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	list, err := c.servers(ctx)
	if err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	off := 0
	for _, s := range list {
		if s.State != "running" {
			off++
		}
	}
	msg := fmt.Sprintf("%d servers in %s", len(list), c.zone)
	if off > 0 {
		msg += fmt.Sprintf(", %d not running", off)
	}
	return sdk.Health{Status: "ok", Message: msg}
}

func state(s string) json.RawMessage { b, _ := json.Marshal(map[string]string{"state": s}); return b }

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Server string `json:"server"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "servers":
		list, err := c.servers(ctx)
		if err != nil {
			return sdk.Result{}, err
		}
		type row struct {
			ID        string   `json:"id"`
			Name      string   `json:"name"`
			State     string   `json:"state"`
			Type      string   `json:"type"`
			Arch      string   `json:"arch,omitempty"`
			PublicIPs []string `json:"publicIps"`
			PrivateIP string   `json:"privateIp,omitempty"`
			Zone      string   `json:"zone"`
			Tags      []string `json:"tags,omitempty"`
			Created   string   `json:"created"`
		}
		out := []row{}
		for _, s := range list {
			r := row{ID: s.ID, Name: s.Name, State: s.State, Type: s.Type, Arch: s.Arch, PublicIPs: []string{}, Zone: s.Zone, Tags: s.Tags, Created: s.Created}
			seen := map[string]bool{}
			for _, ip := range s.PublicIPs {
				if ip.Address != "" && !seen[ip.Address] {
					seen[ip.Address] = true
					r.PublicIPs = append(r.PublicIPs, ip.Address)
				}
			}
			if s.PublicIP != nil && s.PublicIP.Address != "" && !seen[s.PublicIP.Address] {
				r.PublicIPs = append(r.PublicIPs, s.PublicIP.Address)
			}
			if s.PrivateIP != nil {
				r.PrivateIP = *s.PrivateIP
			}
			out = append(out, r)
		}
		return sdk.JSON(out)

	case "clusters":
		type cluster struct {
			ID               string `json:"id"`
			Name             string `json:"name"`
			Status           string `json:"status"`
			Version          string `json:"version"`
			Type             string `json:"type"`
			CNI              string `json:"cni"`
			Region           string `json:"region"`
			UpgradeAvailable bool   `json:"upgrade_available"`
			Created          string `json:"created_at"`
		}
		var out []cluster
		for page := 1; page <= 10; page++ {
			q := url.Values{"page": {strconv.Itoa(page)}, "page_size": {"100"}}
			if c.project != "" {
				q.Set("project_id", c.project)
			}
			var r struct {
				Clusters []cluster `json:"clusters"`
				Total    int       `json:"total_count"`
			}
			if _, err := c.api.Do(ctx, http.MethodGet, "/k8s/v1/regions/"+c.region+"/clusters", q, nil, &r); err != nil {
				return sdk.Result{}, friendly(err, "Kapsule in "+c.region)
			}
			out = append(out, r.Clusters...)
			if len(r.Clusters) < 100 || len(out) >= r.Total {
				break
			}
		}
		type row struct {
			ID               string `json:"id"`
			Name             string `json:"name"`
			Status           string `json:"status"`
			Version          string `json:"version"`
			Type             string `json:"type"`
			CNI              string `json:"cni"`
			Region           string `json:"region"`
			UpgradeAvailable bool   `json:"upgradeAvailable"`
			Created          string `json:"created"`
		}
		rows := []row{}
		for _, k := range out {
			rows = append(rows, row(k))
		}
		return sdk.JSON(rows)

	case "buckets":
		return c.buckets(ctx)

	case "power_on", "power_on_billable", "power_off", "reboot":
		if !uuidRe.MatchString(p.Server) {
			return sdk.Result{}, errors.New("which server? (its id, from Servers)")
		}
		s, err := c.server(ctx, p.Server)
		if err != nil {
			return sdk.Result{}, err
		}
		target := s.Name + " (" + s.ID + ")"
		switch call.Action {
		case "power_on":
			// A server stopped in place is still billed; one that is fully
			// stopped isn't, and powering it on starts billing again.
			if s.State == "stopped" {
				return sdk.Result{}, fmt.Errorf("%s is fully stopped, so powering it on resumes billing for its %s; use power_on_billable", target, s.Type)
			}
			if s.State != "stopped in place" {
				return sdk.Result{}, fmt.Errorf("%s is %s; only a server stopped in place can be powered on here", target, s.State)
			}
		case "power_on_billable":
			if s.State != "stopped" && s.State != "stopped in place" {
				return sdk.Result{}, fmt.Errorf("%s is %s; only a stopped server can be powered on", target, s.State)
			}
		case "power_off":
			if s.State != "running" && s.State != "stopped in place" {
				return sdk.Result{}, fmt.Errorf("%s is %s; only a running server can be powered off", target, s.State)
			}
		case "reboot":
			if s.State != "running" {
				return sdk.Result{}, fmt.Errorf("%s is %s; only a running server can be rebooted", target, s.State)
			}
		}
		want := map[string]string{"power_on": "running", "power_on_billable": "running", "power_off": "stopped", "reboot": "running"}[call.Action]
		if call.DryRun {
			summary := strings.ReplaceAll(call.Action, "_", " ") + " " + target
			ch := sdk.Change{Target: target, Op: call.Action, Before: state(s.State), After: state(want)}
			if call.Action == "power_on_billable" {
				summary = "Power on " + target
				if s.State == "stopped" {
					summary += ": billing resumes for its " + s.Type + " from now on"
				}
				ch.After, _ = json.Marshal(map[string]any{"state": want, "commercial_type": s.Type, "billed": true})
			}
			return sdk.Result{Plan: &sdk.Plan{Summary: summary, Changes: []sdk.Change{ch}}}, nil
		}
		action := map[string]string{"power_on": "poweron", "power_on_billable": "poweron", "power_off": "poweroff", "reboot": "reboot"}[call.Action]
		if _, err := c.api.Do(ctx, http.MethodPost, c.zonePath()+"/servers/"+p.Server+"/action", nil, map[string]string{"action": action}, nil); err != nil {
			return sdk.Result{}, friendly(err, "such server in "+c.zone)
		}
		r, _ := sdk.JSON(map[string]any{"server": target, "was": s.State, "requested": call.Action})
		switch {
		case call.Action == "power_on_billable" && s.State == "stopped":
			r.Undo = sdk.UndoWith("power_off", map[string]string{"server": p.Server}, "Power "+s.Name+" off again")
		case call.Action == "power_off" && s.State == "running":
			// poweroff stops it fully, so powering it on again bills it.
			r.Undo = sdk.UndoWith("power_on_billable", map[string]string{"server": p.Server}, "Power "+s.Name+" on again")
		}
		return r, nil
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}

// buckets lists the region's buckets through the S3 API, signed with the
// API key (access key and secret key).
func (c *conn) buckets(ctx context.Context) (sdk.Result, error) {
	if c.accessKey == "" {
		return sdk.Result{}, errors.New("listing buckets needs the API key's access key in the settings")
	}
	secret, err := c.host.Secret(ctx, c.secret)
	if err != nil {
		return sdk.Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.s3+"/", nil)
	if err != nil {
		return sdk.Result{}, err
	}
	req.Header.Set("User-Agent", "Conduit")
	aws.Sign(req, nil, aws.Credentials{AccessKeyID: c.accessKey, SecretAccessKey: strings.TrimSpace(secret)}, c.region, "s3", c.now())
	res, err := c.http.Do(req)
	if err != nil {
		return sdk.Result{}, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return sdk.Result{}, err
	}
	switch {
	case res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusUnauthorized:
		return sdk.Result{}, errors.New("Scaleway Object Storage refused the access key and secret key (or the key's policy lacks ObjectStorage permissions)")
	case res.StatusCode >= 300:
		return sdk.Result{}, fmt.Errorf("Scaleway Object Storage answered %s", res.Status)
	}
	var r struct {
		Buckets []struct {
			Name    string `xml:"Name"`
			Created string `xml:"CreationDate"`
		} `xml:"Buckets>Bucket"`
	}
	if err := xml.NewDecoder(bytes.NewReader(body)).Decode(&r); err != nil {
		return sdk.Result{}, fmt.Errorf("unexpected answer from Object Storage: %w", err)
	}
	type row struct {
		Name    string `json:"name"`
		Region  string `json:"region"`
		Created string `json:"created"`
	}
	out := []row{}
	for _, b := range r.Buckets {
		out = append(out, row{Name: b.Name, Region: c.region, Created: b.Created})
	}
	return sdk.JSON(out)
}
