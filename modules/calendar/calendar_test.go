package calendar

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

type host struct{ feed string }

func (h host) Secret(_ context.Context, ref string) (string, error) {
	if ref == "secret://feed" {
		return h.feed, nil
	}
	return "", errors.New("no")
}
func (host) Publish(context.Context, sdk.Event) {}
func (host) Log(string, string, ...any)         {}

func TestICSFeedWithRecurrence(t *testing.T) {
	now := time.Now().UTC()
	start := time.Date(now.Year(), now.Month(), now.Day(), 9, 0, 0, 0, time.UTC).AddDate(0, 0, -14)
	ics := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\n" +
		"BEGIN:VEVENT\r\nUID:standup@test\r\nDTSTAMP:20260101T000000Z\r\nSUMMARY:Standup\r\n" +
		"DTSTART:" + start.Format("20060102T150405Z") + "\r\nDTEND:" + start.Add(15*time.Minute).Format("20060102T150405Z") + "\r\n" +
		"RRULE:FREQ=DAILY\r\nEND:VEVENT\r\n" +
		"BEGIN:VEVENT\r\nUID:old@test\r\nDTSTAMP:20260101T000000Z\r\nSUMMARY:Long gone\r\nDTSTART:20200101T100000Z\r\nDTEND:20200101T110000Z\r\nEND:VEVENT\r\n" +
		"END:VCALENDAR\r\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/calendar")
		w.Write([]byte(ics))
	}))
	defer srv.Close()

	m := New()
	ctx := context.Background()
	cfg, _ := json.Marshal(map[string]string{"mode": "ics", "feed": "secret://feed", "timezone": "UTC"})
	if err := m.Configure(ctx, host{feed: srv.URL}, "c1", cfg); err != nil {
		t.Fatal(err)
	}
	r, err := m.Invoke(ctx, sdk.Call{Instance: "c1", Action: "agenda", Input: json.RawMessage(`{"days":7}`)})
	if err != nil {
		t.Fatal(err)
	}
	var evs []Event
	_ = json.Unmarshal(r.Output, &evs)
	if len(evs) != 7 {
		t.Fatalf("want 7 daily standups in a week, got %d: %s", len(evs), r.Output)
	}
	for _, e := range evs {
		if e.Title != "Standup" || !strings.HasSuffix(e.Start, "T09:00:00Z") {
			t.Fatalf("bad occurrence %+v", e)
		}
	}
	if h := m.Health(ctx, "c1"); h.Status != "ok" || h.Message != "1 events today" {
		t.Fatalf("health = %+v", h)
	}
	if _, err := m.Invoke(ctx, sdk.Call{Instance: "c1", Action: "create_event", Input: json.RawMessage(`{"title":"x","start":"2026-11-05"}`)}); err == nil {
		t.Fatal("ICS feeds must be read-only")
	}
}

func TestParseWhen(t *testing.T) {
	loc, _ := time.LoadLocation("Europe/Zurich")
	tm, allDay, err := parseWhen("2026-11-05T14:00", loc)
	if err != nil || allDay || tm.Hour() != 14 || tm.Location() != loc {
		t.Fatalf("%v %v %v", tm, allDay, err)
	}
	if _, allDay, _ := parseWhen("2026-11-05", loc); !allDay {
		t.Fatal("date only should be all day")
	}
	if _, _, err := parseWhen("next tuesday", loc); err == nil {
		t.Fatal("free text should be rejected")
	}
}
