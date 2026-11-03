// Package aws reaches Amazon Web Services: EC2 instances, S3 buckets and
// CloudWatch alarms. Requests are signed with Signature Version 4 (sigv4.go);
// there is no AWS SDK dependency.
package aws

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
	"strings"
	"time"

	"github.com/elchi-dev/conduit/modules/internal/inst"
	"github.com/elchi-dev/conduit/modules/internal/rest"
	"github.com/elchi-dev/conduit/pkg/sdk"
)

// Config is one AWS account's settings.
type Config struct {
	Region          string `json:"region"`
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"` // secret://
	SessionToken    string `json:"sessionToken"`    // secret://, optional
	// Endpoints overrides service URLs ("ec2", "s3", "sts", "monitoring"),
	// for tests or S3-compatible and private endpoints.
	Endpoints map[string]string `json:"endpoints"`
}

type conn struct {
	cfg  Config
	host sdk.Host
}

// Module implements sdk.Module.
type Module struct {
	set  inst.Set[conn]
	HTTP *http.Client
	now  func() time.Time
}

// New returns the AWS module.
func New() *Module { return &Module{HTTP: &http.Client{Timeout: 30 * time.Second}, now: time.Now} }

// client is m.HTTP limited to same-host redirects: the signed request carries
// X-Amz-Security-Token, which Go would forward to another host.
func (m *Module) client() *http.Client { return rest.SameHostOnly(m.HTTP) }

var (
	regionRe   = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-\d$`)
	keyIDRe    = regexp.MustCompile(`^(AKIA|ASIA)[A-Z0-9]{12,20}$`)
	instanceRe = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)
	bucketRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
)

// Manifest implements sdk.Module.
func (m *Module) Manifest() sdk.Manifest {
	inst := `{"type":"object","required":["instance"],"properties":{"instance":{"type":"string","description":"Instance id, i-…"}}}`
	return sdk.Manifest{
		ID: "aws", Name: "AWS", Version: "0.1.0", Category: "Cloud", Icon: "cloud",
		Description: "EC2 instances, S3 buckets and CloudWatch alarms in one AWS account and region.",
		Presets:     []string{"developer", "team"},
		ConfigSchema: sdk.Schema(`{"type":"object","required":["region","accessKeyId","secretAccessKey"],"properties":{
			"region":{"type":"string","default":"us-east-1"},
			"accessKeyId":{"type":"string","description":"Of an IAM user or role limited to what Conduit needs (see the docs for a policy)"},
			"secretAccessKey":{"type":"string","x-secret":true},
			"sessionToken":{"type":"string","x-secret":true,"description":"Only for temporary credentials"}}}`),
		Actions: []sdk.ActionSpec{
			{Name: "ec2_instances", Title: "EC2 instances", Description: "Id, name, state, type and addresses.", Risk: sdk.RiskRead},
			{Name: "ec2_start", Title: "Start an instance", Risk: sdk.RiskWrite, Reversible: true, DryRun: true, Input: sdk.Schema(inst)},
			{Name: "ec2_stop", Title: "Stop an instance", Description: "Data on instance-store volumes is lost, and the public IP changes unless it is an Elastic IP.", Risk: sdk.RiskDestructive, Reversible: true, DryRun: true, Input: sdk.Schema(inst)},
			{Name: "ec2_reboot", Title: "Reboot an instance", Risk: sdk.RiskDestructive, DryRun: true, Input: sdk.Schema(inst)},
			{Name: "s3_buckets", Title: "S3 buckets", Risk: sdk.RiskRead},
			{Name: "s3_list", Title: "Objects in a bucket", Description: "One level at a time, like folders.", Risk: sdk.RiskRead,
				Input: sdk.Schema(`{"type":"object","required":["bucket"],"properties":{"bucket":{"type":"string"},"prefix":{"type":"string","description":"e.g. backups/2026/"}}}`)},
			{Name: "cloudwatch_alarms", Title: "Alarms firing", Description: "CloudWatch alarms in the ALARM state.", Risk: sdk.RiskRead},
		},
	}
}

// Configure implements sdk.Module.
func (m *Module) Configure(_ context.Context, h sdk.Host, id string, raw json.RawMessage) error {
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	if !regionRe.MatchString(c.Region) {
		return errors.New("the region looks like us-east-1 or eu-central-1")
	}
	if !keyIDRe.MatchString(c.AccessKeyID) {
		return errors.New("the access key id starts with AKIA (or ASIA for temporary credentials)")
	}
	if !strings.HasPrefix(c.SecretAccessKey, "secret://") || (c.SessionToken != "" && !strings.HasPrefix(c.SessionToken, "secret://")) {
		return errors.New("store the secret access key (and session token) in the vault and use their secret:// references")
	}
	for svc, u := range c.Endpoints {
		p, err := url.Parse(u)
		if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" {
			return fmt.Errorf("the %s endpoint isn't a URL", svc)
		}
	}
	m.set.Put(id, &conn{cfg: c, host: h})
	return nil
}

// Close implements sdk.Module.
func (m *Module) Close(id string) error { m.set.Delete(id); return nil }

func (c *conn) endpoint(svc string) string {
	if u := c.cfg.Endpoints[svc]; u != "" {
		return strings.TrimRight(u, "/")
	}
	return "https://" + svc + "." + c.cfg.Region + ".amazonaws.com"
}

func (c *conn) creds(ctx context.Context) (Credentials, error) {
	sk, err := c.host.Secret(ctx, c.cfg.SecretAccessKey)
	if err != nil {
		return Credentials{}, err
	}
	cr := Credentials{AccessKeyID: c.cfg.AccessKeyID, SecretAccessKey: sk}
	if c.cfg.SessionToken != "" {
		if cr.SessionToken, err = c.host.Secret(ctx, c.cfg.SessionToken); err != nil {
			return Credentials{}, err
		}
	}
	return cr, nil
}

// Error is an AWS API error.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("AWS: %s (HTTP %d)", e.Code, e.Status)
	}
	return "AWS: " + e.Message + " (" + e.Code + ")"
}

// parseError finds the first Code and Message elements, which covers the
// EC2, query-API and S3 error shapes.
func parseError(status int, b []byte) *Error {
	e := &Error{Status: status}
	d := xml.NewDecoder(bytes.NewReader(b))
	var cur string
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			cur = t.Name.Local
		case xml.CharData:
			s := strings.TrimSpace(string(t))
			if cur == "Code" && e.Code == "" {
				e.Code = s
			}
			if cur == "Message" && e.Message == "" {
				e.Message = s
			}
		case xml.EndElement:
			cur = ""
		}
	}
	if e.Code == "" {
		e.Code = http.StatusText(status)
	}
	return e
}

// do sends a signed request and decodes the XML answer into out.
func (m *Module) do(ctx context.Context, c *conn, svc, method, path string, q url.Values, form url.Values, out any) error {
	cr, err := c.creds(ctx)
	if err != nil {
		return err
	}
	u := c.endpoint(svc) + path
	if len(q) > 0 {
		u += "?" + strings.ReplaceAll(q.Encode(), "+", "%20")
	}
	var body []byte
	if form != nil {
		body = []byte(strings.ReplaceAll(form.Encode(), "+", "%20"))
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	}
	Sign(req, body, cr, c.cfg.Region, svc, m.now())
	res, err := m.client().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		return parseError(res.StatusCode, raw)
	}
	if out != nil {
		if err := xml.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("unexpected answer from AWS %s: %w", svc, err)
		}
	}
	return nil
}

func (m *Module) query(ctx context.Context, c *conn, svc, action, version string, params url.Values, out any) error {
	f := url.Values{"Action": {action}, "Version": {version}}
	for k, v := range params {
		f[k] = v
	}
	return m.do(ctx, c, svc, http.MethodPost, "/", nil, f, out)
}

// Health implements sdk.Module.
func (m *Module) Health(ctx context.Context, id string) sdk.Health {
	c, err := m.set.Get(id)
	if err != nil {
		return sdk.Health{Status: "unconfigured", Message: err.Error()}
	}
	var r struct {
		Account string `xml:"GetCallerIdentityResult>Account"`
		Arn     string `xml:"GetCallerIdentityResult>Arn"`
	}
	if err := m.query(ctx, c, "sts", "GetCallerIdentity", "2011-06-15", nil, &r); err != nil {
		return sdk.Health{Status: "down", Message: err.Error()}
	}
	return sdk.Health{Status: "ok", Message: r.Arn + " in " + c.cfg.Region}
}

type ec2Instance struct {
	ID        string `xml:"instanceId"`
	Type      string `xml:"instanceType"`
	State     string `xml:"instanceState>name"`
	PublicIP  string `xml:"ipAddress"`
	PrivateIP string `xml:"privateIpAddress"`
	Zone      string `xml:"placement>availabilityZone"`
	Launched  string `xml:"launchTime"`
	Tags      []struct {
		Key   string `xml:"key"`
		Value string `xml:"value"`
	} `xml:"tagSet>item"`
}

type stateChange struct {
	ID       string `xml:"instanceId"`
	Current  string `xml:"currentState>name"`
	Previous string `xml:"previousState>name"`
}

// Invoke implements sdk.Module.
func (m *Module) Invoke(ctx context.Context, call sdk.Call) (sdk.Result, error) {
	c, err := m.set.Get(call.Instance)
	if err != nil {
		return sdk.Result{}, err
	}
	var p struct {
		Instance string `json:"instance"`
		Bucket   string `json:"bucket"`
		Prefix   string `json:"prefix"`
	}
	if err := sdk.Decode(call, &p); err != nil {
		return sdk.Result{}, err
	}
	switch call.Action {
	case "ec2_instances":
		type row struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			State     string `json:"state"`
			Type      string `json:"type"`
			PublicIP  string `json:"publicIp,omitempty"`
			PrivateIP string `json:"privateIp,omitempty"`
			Zone      string `json:"zone"`
			Launched  string `json:"launched"`
		}
		out := []row{}
		token := ""
		for page := 0; page < 20; page++ {
			params := url.Values{"MaxResults": {"200"}}
			if token != "" {
				params.Set("NextToken", token)
			}
			var r struct {
				Reservations []struct {
					Instances []ec2Instance `xml:"instancesSet>item"`
				} `xml:"reservationSet>item"`
				NextToken string `xml:"nextToken"`
			}
			if err := m.query(ctx, c, "ec2", "DescribeInstances", "2016-11-15", params, &r); err != nil {
				return sdk.Result{}, err
			}
			for _, res := range r.Reservations {
				for _, i := range res.Instances {
					name := ""
					for _, t := range i.Tags {
						if t.Key == "Name" {
							name = t.Value
						}
					}
					out = append(out, row{ID: i.ID, Name: name, State: i.State, Type: i.Type, PublicIP: i.PublicIP, PrivateIP: i.PrivateIP, Zone: i.Zone, Launched: i.Launched})
				}
			}
			if token = r.NextToken; token == "" {
				break
			}
		}
		return sdk.JSON(out)

	case "ec2_start", "ec2_stop", "ec2_reboot":
		if !instanceRe.MatchString(p.Instance) {
			return sdk.Result{}, errors.New("the instance id looks like i-0123456789abcdef0")
		}
		action := map[string]string{"ec2_start": "StartInstances", "ec2_stop": "StopInstances", "ec2_reboot": "RebootInstances"}[call.Action]
		params := url.Values{"InstanceId.1": {p.Instance}}
		if call.DryRun {
			// EC2 checks permissions and the request without acting, and
			// answers DryRunOperation when it would have succeeded.
			params.Set("DryRun", "true")
			err := m.query(ctx, c, "ec2", action, "2016-11-15", params, nil)
			var ae *Error
			if err != nil && !(errors.As(err, &ae) && ae.Code == "DryRunOperation") {
				return sdk.Result{}, err
			}
			op := map[string]string{"ec2_start": "start", "ec2_stop": "stop", "ec2_reboot": "restart"}[call.Action]
			return sdk.Result{Plan: &sdk.Plan{Summary: strings.ToUpper(op[:1]) + op[1:] + " " + p.Instance + " (AWS confirmed you're allowed to)",
				Changes: []sdk.Change{{Target: p.Instance + " in " + c.cfg.Region, Op: op}}}}, nil
		}
		if call.Action == "ec2_reboot" {
			if err := m.query(ctx, c, "ec2", action, "2016-11-15", params, nil); err != nil {
				return sdk.Result{}, err
			}
			return sdk.JSON(map[string]string{"instance": p.Instance, "rebooting": "true"})
		}
		var r struct {
			Changes []stateChange `xml:"instancesSet>item"`
		}
		if err := m.query(ctx, c, "ec2", action, "2016-11-15", params, &r); err != nil {
			return sdk.Result{}, err
		}
		if len(r.Changes) == 0 {
			return sdk.Result{}, errors.New("AWS didn't report a state change")
		}
		ch := r.Changes[0]
		res, err := sdk.JSON(map[string]string{"instance": ch.ID, "state": ch.Current, "previous": ch.Previous})
		if call.Action == "ec2_start" && ch.Previous == "stopped" {
			res.Undo = sdk.UndoWith("ec2_stop", map[string]string{"instance": p.Instance}, "Stop "+p.Instance+" again")
		}
		if call.Action == "ec2_stop" && ch.Previous == "running" {
			res.Undo = sdk.UndoWith("ec2_start", map[string]string{"instance": p.Instance}, "Start "+p.Instance+" again")
		}
		return res, err

	case "s3_buckets":
		var r struct {
			Buckets []struct {
				Name    string `xml:"Name"`
				Created string `xml:"CreationDate"`
			} `xml:"Buckets>Bucket"`
		}
		if err := m.do(ctx, c, "s3", http.MethodGet, "/", nil, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]string{}
		for _, b := range r.Buckets {
			out = append(out, map[string]string{"name": b.Name, "created": b.Created})
		}
		return sdk.JSON(out)

	case "s3_list":
		if !bucketRe.MatchString(p.Bucket) || strings.Contains(p.Bucket, "..") {
			return sdk.Result{}, errors.New("that isn't a valid bucket name")
		}
		var r struct {
			Contents []struct {
				Key      string `xml:"Key"`
				Size     int64  `xml:"Size"`
				Modified string `xml:"LastModified"`
			} `xml:"Contents"`
			Prefixes  []string `xml:"CommonPrefixes>Prefix"`
			Truncated bool     `xml:"IsTruncated"`
		}
		q := url.Values{"list-type": {"2"}, "delimiter": {"/"}, "max-keys": {"1000"}}
		if p.Prefix != "" {
			q.Set("prefix", p.Prefix)
		}
		// Path-style addressing works for every bucket name, including ones
		// with dots, which break virtual-hosted TLS names.
		if err := m.do(ctx, c, "s3", http.MethodGet, "/"+p.Bucket, q, nil, &r); err != nil {
			return sdk.Result{}, err
		}
		type obj struct {
			Key      string `json:"key"`
			Size     int64  `json:"size,omitempty"`
			Modified string `json:"modified,omitempty"`
			Folder   bool   `json:"folder,omitempty"`
		}
		out := []obj{}
		for _, f := range r.Prefixes {
			out = append(out, obj{Key: f, Folder: true})
		}
		for _, o := range r.Contents {
			out = append(out, obj{Key: o.Key, Size: o.Size, Modified: o.Modified})
		}
		return sdk.JSON(map[string]any{"objects": out, "truncated": r.Truncated})

	case "cloudwatch_alarms":
		var r struct {
			Alarms []struct {
				Name      string `xml:"AlarmName"`
				State     string `xml:"StateValue"`
				Reason    string `xml:"StateReason"`
				Since     string `xml:"StateUpdatedTimestamp"`
				Metric    string `xml:"MetricName"`
				Namespace string `xml:"Namespace"`
			} `xml:"DescribeAlarmsResult>MetricAlarms>member"`
		}
		if err := m.query(ctx, c, "monitoring", "DescribeAlarms", "2010-08-01", url.Values{"StateValue": {"ALARM"}, "MaxRecords": {"100"}}, &r); err != nil {
			return sdk.Result{}, err
		}
		out := []map[string]string{}
		for _, a := range r.Alarms {
			out = append(out, map[string]string{"name": a.Name, "state": a.State, "reason": a.Reason, "since": a.Since, "metric": a.Namespace + " " + a.Metric})
		}
		return sdk.JSON(out)
	}
	return sdk.Result{}, sdk.ErrUnknownAction(call.Action)
}
