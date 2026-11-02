package sdk

import (
	"encoding/json"
	"fmt"
)

// JSON returns a Result whose output is v encoded as JSON.
func JSON(v any) (Result, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return Result{}, err
	}
	return Result{Output: b}, nil
}

// Decode unmarshals a call's input into v. Empty input leaves v unchanged.
func Decode(c Call, v any) error {
	if len(c.Input) == 0 || string(c.Input) == "null" {
		return nil
	}
	if err := json.Unmarshal(c.Input, v); err != nil {
		return fmt.Errorf("invalid input for %s: %w", c.Action, err)
	}
	return nil
}

// UndoWith builds an undo token for an action and input.
func UndoWith(action string, input any, description string) *Undo {
	b, _ := json.Marshal(input)
	return &Undo{Action: action, Input: b, Description: description}
}

// Schema is a convenience for writing JSON Schema literals in manifests.
func Schema(s string) json.RawMessage { return json.RawMessage(s) }

// ErrUnknownAction is the standard error for an action a module does not have.
func ErrUnknownAction(action string) error { return fmt.Errorf("unknown action %q", action) }
