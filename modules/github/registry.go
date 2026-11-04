package github

import (
	"context"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

// runFunc runs one of the table-driven actions.
type runFunc func(ctx context.Context, a *account, p args, c sdk.Call) (sdk.Result, error)

type action struct {
	spec sdk.ActionSpec
	run  runFunc
}

var (
	actionOrder []string
	actionTable = map[string]action{}
)

// def registers an action. Files register theirs in init, by area.
func def(spec sdk.ActionSpec, run runFunc) {
	if _, dup := actionTable[spec.Name]; dup {
		panic("github: duplicate action " + spec.Name)
	}
	actionOrder = append(actionOrder, spec.Name)
	actionTable[spec.Name] = action{spec: spec, run: run}
}

func tableSpecs() []sdk.ActionSpec {
	out := make([]sdk.ActionSpec, 0, len(actionOrder))
	for _, n := range actionOrder {
		out = append(out, actionTable[n].spec)
	}
	return out
}

// Shorthands for the spec flags most actions use.
func read(name, title, desc string, in []byte) sdk.ActionSpec {
	return sdk.ActionSpec{Name: name, Title: title, Description: desc, Risk: sdk.RiskRead, Input: in}
}

func write(name, title, desc string, in []byte, reversible bool) sdk.ActionSpec {
	return sdk.ActionSpec{Name: name, Title: title, Description: desc, Risk: sdk.RiskWrite, Input: in, DryRun: true, Reversible: reversible}
}

func destructive(name, title, desc string, in []byte, reversible bool) sdk.ActionSpec {
	return sdk.ActionSpec{Name: name, Title: title, Description: desc, Risk: sdk.RiskDestructive, Input: in, DryRun: true, Reversible: reversible}
}
