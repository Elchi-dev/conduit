package core

import "context"

type actorKey struct{}

// WithActor returns ctx carrying actor as the caller of a module call.
// The engine sets it on the context it hands a module's Invoke (and the
// dry run it computes for an approval), so module code that makes nested
// calls on the caller's behalf, like the daily brief, can make them as that
// caller and never as someone with more rights.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

// ActorFrom returns the caller the engine is running a module call for.
func ActorFrom(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorKey{}).(Actor)
	return a, ok && a.Kind != ""
}
