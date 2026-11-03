package ai

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/elchi-dev/conduit/internal/core"
)

// Conversation is a chat with the built-in assistant.
type Conversation struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Provider  string    `json:"provider"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	Messages  []Msg     `json:"messages,omitempty"`
}

// Agent is the built-in assistant.
type Agent struct {
	DB        *sql.DB
	Providers *Providers
}

// Step is one streamed piece of the assistant's work.
type Step struct {
	Type         string          `json:"type"` // text, tool, result, done, error
	Text         string          `json:"text,omitempty"`
	Tool         string          `json:"tool,omitempty"`
	Title        string          `json:"title,omitempty"`
	Args         json.RawMessage `json:"args,omitempty"`
	IsError      bool            `json:"isError,omitempty"`
	Approval     *core.Approval  `json:"approval,omitempty"`
	Audit        int64           `json:"audit,omitempty"`
	Conversation string          `json:"conversation,omitempty"`
}

const maxTurns = 12

func systemPrompt(user string) string {
	return fmt.Sprintf(`You are the assistant inside Conduit, the control panel %s uses for their computers, servers, containers, mail, calendars, secrets and more.
It is %s.

How to work:
- Use tools to look before you answer; don't guess about the user's systems. Call conduit_overview when you need to know what's connected.
- Reads are free. Changes may need the user's approval: when a tool says it is waiting for approval, stop and tell the user plainly what you asked to do and why. They approve it in the card shown in this chat; then they'll tell you to continue and you call the same tool again.
- Before a risky change, use conduit_preview when the tool supports it and show the user what will change.
- When something broke, use conduit_what_changed to find what happened around that time before suggesting fixes.
- Never try to get around a denial or a rule. Never reveal secret values unless the user explicitly asks for that secret.
- Be brief and concrete. Use the user's language. Name systems by their names, not their IDs.`, user, time.Now().Format("Monday 2 January 2006, 15:04 MST"))
}

// Chat runs one user turn: the model may call tools several times before
// answering. Each step is passed to emit as it happens.
func (a *Agent) Chat(ctx context.Context, tb *Toolbox, userID, userName, convID, text string, emit func(Step)) error {
	conv, err := a.load(ctx, userID, convID)
	if err != nil {
		return err
	}
	pr, err := a.Providers.Get(ctx, conv.Provider)
	if err != nil {
		return err
	}
	if conv.ID == "" {
		conv = Conversation{ID: core.NewID("conv"), Title: title(text), Provider: pr.ID, CreatedAt: time.Now().UTC()}
		if _, err := a.DB.ExecContext(ctx, `INSERT INTO ai_conversations (id, user_id, title, provider, created_at, updated_at) VALUES (?,?,?,?,?,?)`,
			conv.ID, userID, conv.Title, pr.ID, conv.CreatedAt.Format(time.RFC3339Nano), conv.CreatedAt.Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	msgs := conv.Messages
	add := func(m Msg) {
		msgs = append(msgs, m)
		b, _ := json.Marshal(m)
		_, _ = a.DB.ExecContext(context.WithoutCancel(ctx), `INSERT INTO ai_messages (conversation, seq, body, created_at) VALUES (?,?,?,?)`,
			conv.ID, len(msgs), string(b), time.Now().UTC().Format(time.RFC3339Nano))
	}
	add(Msg{Role: "user", Text: text})
	defer func() {
		_, _ = a.DB.ExecContext(context.WithoutCancel(ctx), `UPDATE ai_conversations SET updated_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339Nano), conv.ID)
		emit(Step{Type: "done", Conversation: conv.ID})
	}()

	tools := tb.Tools()
	sys := systemPrompt(userName)
	for turn := 0; turn < maxTurns; turn++ {
		reply, err := a.Providers.Complete(ctx, pr, sys, msgs, tools)
		if err != nil {
			emit(Step{Type: "error", Text: err.Error()})
			return nil
		}
		add(reply)
		if reply.Text != "" {
			emit(Step{Type: "text", Text: reply.Text})
		}
		if len(reply.ToolCalls) == 0 {
			return nil
		}
		waiting := false
		for _, c := range reply.ToolCalls {
			title := c.Name
			for _, t := range tools {
				if t.Name == c.Name && t.Title != "" {
					title = t.Title
				}
			}
			emit(Step{Type: "tool", Tool: c.Name, Title: title, Args: c.Args})
			res := tb.Call(ctx, c.Name, c.Args)
			emit(Step{Type: "result", Tool: c.Name, Text: truncate(res.Text, 4000), IsError: res.IsError, Approval: res.Pending, Audit: res.Audit})
			add(Msg{Role: "tool", ToolCallID: c.ID, Text: res.Text, IsError: res.IsError})
			if res.Pending != nil {
				waiting = true
			}
		}
		if waiting {
			// Let the model explain the pending request once, then stop and
			// wait for the person instead of looping.
			final, err := a.Providers.Complete(ctx, pr, sys, msgs, nil)
			if err == nil && final.Text != "" {
				add(final)
				emit(Step{Type: "text", Text: final.Text})
			}
			return nil
		}
	}
	emit(Step{Type: "error", Text: "Stopped after many steps without an answer. Try asking more specifically."})
	return nil
}

func title(text string) string {
	t := strings.Join(strings.Fields(text), " ")
	if len(t) > 60 {
		t = t[:57] + "…"
	}
	return t
}

func (a *Agent) load(ctx context.Context, userID, id string) (Conversation, error) {
	if id == "" {
		return Conversation{}, nil
	}
	var c Conversation
	var cr, up string
	err := a.DB.QueryRowContext(ctx, `SELECT id, title, provider, created_at, updated_at FROM ai_conversations WHERE id = ? AND user_id = ?`, id, userID).
		Scan(&c.ID, &c.Title, &c.Provider, &cr, &up)
	if errors.Is(err, sql.ErrNoRows) {
		return c, errors.New("no such conversation")
	}
	if err != nil {
		return c, err
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339Nano, cr)
	c.UpdatedAt, _ = time.Parse(time.RFC3339Nano, up)
	rows, err := a.DB.QueryContext(ctx, `SELECT body FROM ai_messages WHERE conversation = ? ORDER BY seq`, id)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var b string
		if err := rows.Scan(&b); err != nil {
			return c, err
		}
		var m Msg
		_ = json.Unmarshal([]byte(b), &m)
		c.Messages = append(c.Messages, m)
	}
	return c, rows.Err()
}

// Get returns a conversation with its messages.
func (a *Agent) Get(ctx context.Context, userID, id string) (Conversation, error) {
	return a.load(ctx, userID, id)
}

// List returns a user's conversations, newest first.
func (a *Agent) List(ctx context.Context, userID string) ([]Conversation, error) {
	rows, err := a.DB.QueryContext(ctx, `SELECT id, title, provider, created_at, updated_at FROM ai_conversations WHERE user_id = ? ORDER BY updated_at DESC LIMIT 100`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Conversation{}
	for rows.Next() {
		var c Conversation
		var cr, up string
		if err := rows.Scan(&c.ID, &c.Title, &c.Provider, &cr, &up); err != nil {
			return nil, err
		}
		c.CreatedAt, _ = time.Parse(time.RFC3339Nano, cr)
		c.UpdatedAt, _ = time.Parse(time.RFC3339Nano, up)
		out = append(out, c)
	}
	return out, rows.Err()
}

// Delete removes a conversation.
func (a *Agent) Delete(ctx context.Context, userID, id string) error {
	_, err := a.DB.ExecContext(ctx, `DELETE FROM ai_conversations WHERE id = ? AND user_id = ?`, id, userID)
	return err
}
