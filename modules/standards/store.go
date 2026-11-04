package standards

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Keep is how many earlier versions are kept per standard or toolkit.
const Keep = 20

const maxFile = 1 << 20

// store keeps one JSON file per standard and per toolkit, so the folder can
// be put under git (the module holds its lock around every call):
//
//	standards/<id>.json
//	toolkits/<id>.json
//	history/standards/<id>/<version>.json   (last 20, newest has the largest version)
//	history/toolkits/<id>/<version>.json
type store struct {
	dir  string
	last int64 // last version handed out, so versions are unique and increasing
}

// kinds of stored things.
const (
	kStandard = "standards"
	kToolkit  = "toolkits"
)

func (s *store) path(kind, id string) string {
	return filepath.Join(s.dir, kind, id+".json")
}

func (s *store) historyDir(kind, id string) string {
	return filepath.Join(s.dir, "history", kind, id)
}

func writeAtomic(path string, b []byte) error {
	if len(b) > maxFile {
		return errors.New("too large (1 MiB at most)")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *store) readRaw(kind, id string) ([]byte, error) {
	if !idRe.MatchString(id) {
		return nil, fmt.Errorf("%q isn't a usable id", id)
	}
	return os.ReadFile(s.path(kind, id))
}

func (s *store) getStandard(id string) (Standard, error) {
	var st Standard
	b, err := s.readRaw(kStandard, id)
	if errors.Is(err, fs.ErrNotExist) {
		return st, fmt.Errorf("there's no standard %q", id)
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("standard %s is damaged: %w", id, err)
	}
	st.ID = id
	return st, nil
}

func (s *store) getToolkit(id string) (Toolkit, error) {
	var k Toolkit
	b, err := s.readRaw(kToolkit, id)
	if errors.Is(err, fs.ErrNotExist) {
		return k, fmt.Errorf("there's no toolkit %q", id)
	}
	if err != nil {
		return k, err
	}
	if err := json.Unmarshal(b, &k); err != nil {
		return k, fmt.Errorf("toolkit %s is damaged: %w", id, err)
	}
	k.ID = id
	return k, nil
}

func (s *store) all(kind string) ([][]byte, error) {
	ents, err := os.ReadDir(filepath.Join(s.dir, kind))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if e.IsDir() || !ok || !idRe.MatchString(id) {
			continue
		}
		if b, err := os.ReadFile(filepath.Join(s.dir, kind, e.Name())); err == nil {
			out = append(out, b)
		}
	}
	return out, nil
}

func (s *store) standards() ([]Standard, error) {
	raws, err := s.all(kStandard)
	out := []Standard{}
	for _, b := range raws {
		var st Standard
		if json.Unmarshal(b, &st) == nil && st.ID != "" {
			out = append(out, st)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].Title < out[j].Title
	})
	return out, err
}

func (s *store) toolkits() ([]Toolkit, error) {
	raws, err := s.all(kToolkit)
	out := []Toolkit{}
	for _, b := range raws {
		var k Toolkit
		if json.Unmarshal(b, &k) == nil && k.ID != "" {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Title < out[j].Title })
	return out, err
}

func (s *store) nextVersion() string {
	v := time.Now().UnixNano()
	if v <= s.last {
		v = s.last + 1
	}
	s.last = v
	return strconv.FormatInt(v, 10)
}

// snapshot copies the current file (if any) into history and returns its
// version, or "" when there was nothing to keep. It trims to Keep versions.
func (s *store) snapshot(kind, id string) (string, error) {
	b, err := os.ReadFile(s.path(kind, id))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	v := s.nextVersion()
	if err := writeAtomic(filepath.Join(s.historyDir(kind, id), v+".json"), b); err != nil {
		return "", err
	}
	vs, _ := s.versions(kind, id)
	for len(vs) > Keep {
		_ = os.Remove(filepath.Join(s.historyDir(kind, id), vs[len(vs)-1]+".json"))
		vs = vs[:len(vs)-1]
	}
	return v, nil
}

// versions lists stored versions, newest first.
func (s *store) versions(kind, id string) ([]string, error) {
	ents, err := os.ReadDir(s.historyDir(kind, id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var vs []int64
	for _, e := range ents {
		if n, ok := strings.CutSuffix(e.Name(), ".json"); ok {
			if v, err := strconv.ParseInt(n, 10, 64); err == nil {
				vs = append(vs, v)
			}
		}
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i] > vs[j] })
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = strconv.FormatInt(v, 10)
	}
	return out, nil
}

func (s *store) version(kind, id, v string) ([]byte, error) {
	if _, err := strconv.ParseInt(v, 10, 64); err != nil || !idRe.MatchString(id) {
		return nil, fmt.Errorf("no version %q of %s", v, id)
	}
	b, err := os.ReadFile(filepath.Join(s.historyDir(kind, id), v+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("version %s of %s is no longer kept", v, id)
	}
	return b, err
}

// put writes a value after keeping the previous one in history. It returns
// the undo step that brings the previous state back.
func (s *store) put(kind, id string, v any) (Step, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return Step{}, err
	}
	prev, err := s.snapshot(kind, id)
	if err != nil {
		return Step{}, err
	}
	if err := writeAtomic(s.path(kind, id), append(b, '\n')); err != nil {
		return Step{}, err
	}
	return stepFor(kind, id, prev), nil
}

// remove deletes a value after keeping it in history.
func (s *store) remove(kind, id string) (Step, error) {
	prev, err := s.snapshot(kind, id)
	if err != nil {
		return Step{}, err
	}
	if prev == "" {
		return Step{}, fmt.Errorf("there's no %s %q", strings.TrimSuffix(kind, "s"), id)
	}
	if err := os.Remove(s.path(kind, id)); err != nil {
		return Step{}, err
	}
	return stepFor(kind, id, prev), nil
}

// Step is one restore instruction: bring id back to a version, or remove it
// when it didn't exist (Absent).
type Step struct {
	Kind    string `json:"kind"` // "standard" or "toolkit"
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
	Absent  bool   `json:"absent,omitempty"`
}

func stepFor(kind, id, prev string) Step {
	k := "standard"
	if kind == kToolkit {
		k = "toolkit"
	}
	if prev == "" {
		return Step{Kind: k, ID: id, Absent: true}
	}
	return Step{Kind: k, ID: id, Version: prev}
}

// apply runs one restore step and returns the step that reverses it.
func (s *store) apply(st Step) (Step, error) {
	kind := kStandard
	if st.Kind == "toolkit" {
		kind = kToolkit
	}
	if !idRe.MatchString(st.ID) {
		return Step{}, fmt.Errorf("%q isn't a usable id", st.ID)
	}
	if st.Absent {
		prev, err := s.snapshot(kind, st.ID)
		if err != nil {
			return Step{}, err
		}
		if err := os.Remove(s.path(kind, st.ID)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return Step{}, err
		}
		return stepFor(kind, st.ID, prev), nil
	}
	b, err := s.version(kind, st.ID, st.Version)
	if err != nil {
		return Step{}, err
	}
	prev, err := s.snapshot(kind, st.ID)
	if err != nil {
		return Step{}, err
	}
	if err := writeAtomic(s.path(kind, st.ID), b); err != nil {
		return Step{}, err
	}
	return stepFor(kind, st.ID, prev), nil
}
