// Command conduit is a command-line client for a Conduit daemon: run
// actions, follow events, check approvals and the audit log from a terminal
// or a script. It uses an API key, so everything it does goes through the
// daemon's agent and key rules like any other program.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"

	"github.com/elchi-dev/conduit/internal/version"
)

// Exit codes.
const (
	exitOK      = 0
	exitError   = 1
	exitUsage   = 2
	exitPending = 3
	exitDenied  = 4
)

func cliVersion() string { return version.Version }

// env is everything a command needs; tests replace its parts.
type env struct {
	ctx    context.Context
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string
	isTTY  bool

	// global flags
	url, key, profile string
	json              bool
}

// usageError makes the command exit with 2 and print its usage.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

// exitError carries a specific exit code.
type exitErr struct {
	code int
	msg  string
}

func (e exitErr) Error() string { return e.msg }

type command struct {
	name    string
	args    string // usage after the name
	summary string
	flags   []string // value flags this command takes (without --), e.g. "module"
	bools   []string // boolean flags
	run     func(e *env, a *args) error
}

var commands []command

func init() {
	commands = []command{
		{name: "login", summary: "Save the daemon's address and an API key", flags: []string{"url", "key"}, run: cmdLogin},
		{name: "logout", summary: "Forget the saved key for this profile", run: cmdLogout},
		{name: "whoami", summary: "Show which key and account you're using", run: cmdWhoami},
		{name: "modules", summary: "List installed modules", run: cmdModules},
		{name: "instances", summary: "List set-up instances (what actions run on)", flags: []string{"module"}, run: cmdInstances},
		{name: "actions", args: "<instance>", summary: "List an instance's actions and their risk", run: cmdActions},
		{name: "run", args: "<instance> <action> [key=value ...]", summary: "Run an action", flags: []string{"input"}, bools: []string{"dry-run", "wait"}, run: cmdRun},
		{name: "approvals", summary: "List approvals", bools: []string{"pending"}, run: cmdApprovals},
		{name: "approve", args: "<id>", summary: "Approve a request (people only; keys are refused)", run: cmdDecide(true)},
		{name: "deny", args: "<id>", summary: "Deny a request (people only; keys are refused)", run: cmdDecide(false)},
		{name: "audit", summary: "Show the audit log, newest first", flags: []string{"module", "limit"}, bools: []string{"follow"}, run: cmdAudit},
		{name: "undo", args: "<seq>", summary: "Undo an audited action by its number", run: cmdUndo},
		{name: "events", summary: "Follow live events", flags: []string{"type"}, run: cmdEvents},
		{name: "vault", args: "list", summary: "List secret names (never values)", run: cmdVault},
		{name: "automations", args: "list | run <id>", summary: "List or start automations", run: cmdAutomations},
		{name: "panic", summary: "Pull the emergency stop", bools: []string{"yes"}, run: cmdPanic},
		{name: "completion", args: "bash|zsh|fish|powershell", summary: "Print a shell completion script", run: cmdCompletion},
		{name: "version", summary: "Show the version", run: cmdVersion},
		{name: "help", args: "[command]", summary: "Show help", run: cmdHelp},
	}
}

func findCommand(name string) *command {
	for i := range commands {
		if commands[i].name == name {
			return &commands[i]
		}
	}
	return nil
}

// args holds a command's positional arguments and flags.
type args struct {
	pos   []string
	vals  map[string]string
	bools map[string]bool
}

func (a *args) val(name string) string { return a.vals[name] }

// parse splits argv into global flags, command flags and positionals.
// Flags may come anywhere; "--" ends flag parsing.
func parse(cmd *command, argv []string, e *env) (*args, error) {
	a := &args{vals: map[string]string{}, bools: map[string]bool{}}
	isVal := map[string]bool{"url": true, "key": true, "profile": true}
	isBool := map[string]bool{"json": true, "help": true}
	if cmd != nil {
		for _, f := range cmd.flags {
			isVal[f] = true
		}
		for _, f := range cmd.bools {
			isBool[f] = true
		}
	}
	for i := 0; i < len(argv); i++ {
		s := argv[i]
		if s == "--" {
			a.pos = append(a.pos, argv[i+1:]...)
			break
		}
		if !strings.HasPrefix(s, "-") || s == "-" {
			a.pos = append(a.pos, s)
			continue
		}
		name := strings.TrimLeft(s, "-")
		value, hasValue := "", false
		if k, v, ok := strings.Cut(name, "="); ok {
			name, value, hasValue = k, v, true
		}
		if name == "h" {
			name = "help"
		}
		switch {
		case isBool[name]:
			if hasValue {
				a.bools[name] = value == "true" || value == "1"
			} else {
				a.bools[name] = true
			}
		case isVal[name]:
			if !hasValue {
				if i+1 >= len(argv) {
					return nil, usageError{fmt.Sprintf("--%s needs a value", name)}
				}
				i++
				value = argv[i]
			}
			a.vals[name] = value
		default:
			return nil, usageError{fmt.Sprintf("unknown option --%s", name)}
		}
	}
	if v, ok := a.vals["url"]; ok {
		e.url = v
	}
	if v, ok := a.vals["key"]; ok {
		e.key = v
	}
	if v, ok := a.vals["profile"]; ok {
		e.profile = v
	}
	if a.bools["json"] {
		e.json = true
	}
	return a, nil
}

// connect resolves the address and key: flags, then CONDUIT_URL and
// CONDUIT_API_KEY, then the profile in the config file.
func (e *env) connect() (*client, error) {
	url, key := e.url, e.key
	if url == "" {
		url = e.getenv("CONDUIT_URL")
	}
	if key == "" {
		key = e.getenv("CONDUIT_API_KEY")
	}
	if url == "" || key == "" {
		cfg, err := loadConfig()
		if err != nil {
			return nil, err
		}
		name := e.profileName(cfg)
		p := cfg.Profiles[name]
		if url == "" {
			url = p.URL
		}
		if key == "" {
			key = p.Key
		}
	}
	if url == "" {
		url = "http://127.0.0.1:7600"
	}
	if key == "" {
		return nil, errors.New("no API key: run `conduit login`, set CONDUIT_API_KEY, or pass --key")
	}
	return newClient(url, key), nil
}

func (e *env) profileName(cfg config) string {
	switch {
	case e.profile != "":
		return e.profile
	case e.getenv("CONDUIT_PROFILE") != "":
		return e.getenv("CONDUIT_PROFILE")
	case cfg.Default != "":
		return cfg.Default
	}
	return "default"
}

// run executes argv (without the program name) and returns the exit code.
func run(e *env, argv []string) int {
	if len(argv) == 0 {
		_ = cmdHelp(e, &args{})
		return exitUsage
	}
	name := argv[0]
	if name == "-h" || name == "--help" {
		name = "help"
	}
	if name == "--version" {
		name = "version"
	}
	cmd := findCommand(name)
	if cmd == nil {
		fmt.Fprintf(e.stderr, "conduit: unknown command %q (see `conduit help`)\n", name)
		return exitUsage
	}
	a, err := parse(cmd, argv[1:], e)
	if err == nil && a.bools["help"] {
		printCommandHelp(e.stdout, cmd)
		return exitOK
	}
	if err == nil {
		err = cmd.run(e, a)
	}
	if err == nil {
		return exitOK
	}
	var ue usageError
	var xe exitErr
	var ae *apiError
	switch {
	case errors.As(err, &ue):
		fmt.Fprintf(e.stderr, "conduit %s: %s\n", cmd.name, ue.msg)
		fmt.Fprintf(e.stderr, "usage: conduit %s %s\n", cmd.name, cmd.args)
		return exitUsage
	case errors.As(err, &xe):
		if xe.msg != "" {
			fmt.Fprintln(e.stderr, xe.msg)
		}
		return xe.code
	case errors.As(err, &ae) && ae.Status == 403:
		fmt.Fprintf(e.stderr, "conduit: not allowed: %s\n", ae.Error())
		return exitDenied
	}
	fmt.Fprintf(e.stderr, "conduit: %s\n", err)
	return exitError
}

func cmdHelp(e *env, a *args) error {
	if len(a.pos) > 0 {
		if c := findCommand(a.pos[0]); c != nil {
			printCommandHelp(e.stdout, c)
			return nil
		}
		return usageError{"no such command " + a.pos[0]}
	}
	w := e.stdout
	fmt.Fprintln(w, "conduit: run actions, follow events and check approvals on a Conduit daemon.")
	fmt.Fprintln(w, "\nUsage: conduit <command> [options]\n\nCommands:")
	names := make([]string, 0, len(commands))
	for _, c := range commands {
		names = append(names, c.name)
	}
	sort.Strings(names)
	for _, n := range names {
		c := findCommand(n)
		fmt.Fprintf(w, "  %-12s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w, "\nOptions for every command:")
	fmt.Fprintln(w, "  --url URL        the daemon (default: saved profile, CONDUIT_URL, http://127.0.0.1:7600)")
	fmt.Fprintln(w, "  --key KEY        API key (default: saved profile or CONDUIT_API_KEY)")
	fmt.Fprintln(w, "  --profile NAME   use a saved profile (CONDUIT_PROFILE)")
	fmt.Fprintln(w, "  --json           print JSON instead of tables")
	fmt.Fprintln(w, "\nExit codes: 0 ok, 1 error, 2 usage, 3 waiting for approval, 4 not allowed.")
	return nil
}

func printCommandHelp(w io.Writer, c *command) {
	fmt.Fprintf(w, "conduit %s %s\n\n%s\n", c.name, c.args, c.summary)
	if len(c.flags)+len(c.bools) > 0 {
		fmt.Fprintln(w, "\nOptions:")
		for _, f := range c.flags {
			fmt.Fprintf(w, "  --%s VALUE\n", f)
		}
		for _, f := range c.bools {
			fmt.Fprintf(w, "  --%s\n", f)
		}
	}
}

func cmdVersion(e *env, _ *args) error {
	if e.json {
		return printJSON(e, version.Get())
	}
	fmt.Fprintf(e.stdout, "conduit %s\n", version.Version)
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fi, _ := os.Stdout.Stat()
	e := &env{ctx: ctx, stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, getenv: os.Getenv,
		isTTY: fi != nil && fi.Mode()&os.ModeCharDevice != 0}
	os.Exit(run(e, os.Args[1:]))
}
