package main

import (
	"fmt"
	"sort"
	"strings"
)

func commandNames() []string {
	out := []string{}
	for _, c := range commands {
		out = append(out, c.name)
	}
	sort.Strings(out)
	return out
}

func flagNames(c *command) []string {
	out := []string{"--url", "--key", "--profile", "--json", "--help"}
	for _, f := range c.flags {
		out = append(out, "--"+f)
	}
	for _, f := range c.bools {
		out = append(out, "--"+f)
	}
	return out
}

// cmdCompletion prints a completion script. Command names and flags are
// completed; instance ids are completed by asking the daemon (`conduit
// instances --json`), which works once you've logged in.
func cmdCompletion(e *env, a *args) error {
	if len(a.pos) != 1 {
		return usageError{"name a shell: bash, zsh, fish or powershell"}
	}
	names := strings.Join(commandNames(), " ")
	switch a.pos[0] {
	case "bash", "zsh":
		var cases strings.Builder
		for _, c := range commands {
			fmt.Fprintf(&cases, "    %s) flags=%q ;;\n", c.name, strings.Join(flagNames(&c), " "))
		}
		script := `# conduit completion for bash (zsh: autoload -U bashcompinit && bashcompinit first)
_conduit_instances() {
  conduit instances --json 2>/dev/null | sed -n 's/.*"id": *"\([^"]*\)".*/\1/p'
}
_conduit() {
  local cur cmd flags
  cur="${COMP_WORDS[COMP_CWORD]}"
  cmd="${COMP_WORDS[1]}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "` + names + `" -- "$cur") )
    return
  fi
  case "$cmd" in
` + cases.String() + `  esac
  if [[ "$cur" == -* ]]; then
    COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
  elif [ "$COMP_CWORD" -eq 2 ]; then
    case "$cmd" in
      run|actions) COMPREPLY=( $(compgen -W "$(_conduit_instances)" -- "$cur") ) ;;
      completion) COMPREPLY=( $(compgen -W "bash zsh fish powershell" -- "$cur") ) ;;
      vault) COMPREPLY=( $(compgen -W "list" -- "$cur") ) ;;
      automations) COMPREPLY=( $(compgen -W "list run" -- "$cur") ) ;;
      help) COMPREPLY=( $(compgen -W "` + names + `" -- "$cur") ) ;;
    esac
  fi
}
complete -F _conduit conduit
`
		if a.pos[0] == "zsh" {
			script = "autoload -U +X bashcompinit && bashcompinit\n" + script
		}
		fmt.Fprint(e.stdout, script)
	case "fish":
		var b strings.Builder
		b.WriteString("# conduit completion for fish\ncomplete -c conduit -f\n")
		for _, c := range commands {
			fmt.Fprintf(&b, "complete -c conduit -n '__fish_use_subcommand' -a %s -d %q\n", c.name, c.summary)
			for _, f := range flagNames(&c) {
				fmt.Fprintf(&b, "complete -c conduit -n '__fish_seen_subcommand_from %s' -l %s\n", c.name, strings.TrimPrefix(f, "--"))
			}
		}
		b.WriteString("function __conduit_instances\n    conduit instances --json 2>/dev/null | string match -rg '\"id\": *\"([^\"]*)\"'\nend\n")
		b.WriteString("complete -c conduit -n '__fish_seen_subcommand_from run actions' -a '(__conduit_instances)'\n")
		fmt.Fprint(e.stdout, b.String())
	case "powershell":
		quoted := []string{}
		for _, n := range commandNames() {
			quoted = append(quoted, "'"+n+"'")
		}
		fmt.Fprintf(e.stdout, `# conduit completion for PowerShell: add to your $PROFILE
Register-ArgumentCompleter -Native -CommandName conduit -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $commands = @(%s)
    $words = $commandAst.CommandElements | ForEach-Object { $_.ToString() }
    if ($words.Count -le 2) {
        $commands | Where-Object { $_ -like "$wordToComplete*" } |
            ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
    } elseif ($words[1] -in @('run', 'actions') -and $words.Count -le 3) {
        (conduit instances --json 2>$null | ConvertFrom-Json) | ForEach-Object { $_.id } |
            Where-Object { $_ -like "$wordToComplete*" } |
            ForEach-Object { [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_) }
    }
}
`, strings.Join(quoted, ", "))
	default:
		return usageError{"shells: bash, zsh, fish, powershell"}
	}
	return nil
}
