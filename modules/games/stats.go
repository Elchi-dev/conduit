package games

import (
	"math"
	"sort"
	"time"
)

// DayStat is the play time of one calendar day.
type DayStat struct {
	Date    string `json:"date"` // YYYY-MM-DD, in the computer's time zone
	Seconds int64  `json:"seconds"`
}

// GameStat is one game's play in a period.
type GameStat struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Launcher   string `json:"launcher"`
	Seconds    int64  `json:"seconds"`
	Sessions   int    `json:"sessions"`
	LastPlayed string `json:"lastPlayed,omitempty"`
}

// Streak counts consecutive days with any play.
type Streak struct {
	Current int    `json:"current"`
	Longest int    `json:"longest"`
	Since   string `json:"since,omitempty"` // first day of the current streak
}

// SeriesOut is the {"series": [...]} chart shape the web app draws.
type SeriesOut struct {
	Name   string       `json:"name"`
	Points [][2]float64 `json:"points"`
}

// Stats summarises recorded play over the last Days days.
type Stats struct {
	From           string      `json:"from"`
	To             string      `json:"to"`
	Days           int         `json:"days"`
	GameID         string      `json:"gameId,omitempty"`
	TotalSeconds   int64       `json:"totalSeconds"`
	TotalHours     float64     `json:"totalHours"`
	Sessions       int         `json:"sessions"`
	AverageSession int64       `json:"averageSessionSeconds"`
	LongestSession *Session    `json:"longestSession,omitempty"`
	DaysPlayed     int         `json:"daysPlayed"`
	PerDay         []DayStat   `json:"perDay"`
	PerGame        []GameStat  `json:"perGame"`
	Top            []GameStat  `json:"top"`
	Streak         Streak      `json:"streak"`
	Series         []SeriesOut `json:"series"`
}

func dayStart(t time.Time, loc *time.Location) time.Time {
	t = t.In(loc)
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
}

// splitDays spreads a session over the calendar days it touches.
func splitDays(s Session, loc *time.Location, add func(day time.Time, secs int64)) {
	start, end := s.Start, s.End
	if !end.After(start) {
		return
	}
	for d := dayStart(start, loc); d.Before(end); d = d.AddDate(0, 0, 1) {
		next := d.AddDate(0, 0, 1)
		a, b := maxTime(start, d), minTime(end, next)
		if b.After(a) {
			add(d, int64(b.Sub(a).Seconds()))
		}
	}
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// computeStats builds Stats for the days ending today. With gameID, only that
// game's sessions count. Streaks look at the whole history.
func computeStats(all []Session, now time.Time, days int, gameID string, loc *time.Location) Stats {
	if days <= 0 {
		days = 30
	}
	if days > 3660 {
		days = 3660
	}
	today := dayStart(now, loc)
	from := today.AddDate(0, 0, -(days - 1))
	st := Stats{From: from.Format("2006-01-02"), To: today.Format("2006-01-02"), Days: days, GameID: gameID,
		PerDay: []DayStat{}, PerGame: []GameStat{}, Top: []GameStat{}}
	perDay := map[string]int64{}
	everDay := map[string]bool{}
	perGame := map[string]*GameStat{}
	var longest *Session
	for _, s := range all {
		if gameID != "" && s.GameID != gameID {
			continue
		}
		splitDays(s, loc, func(d time.Time, secs int64) {
			everDay[d.Format("2006-01-02")] = true
		})
		if !s.End.After(from) {
			continue
		}
		in := false
		splitDays(s, loc, func(d time.Time, secs int64) {
			if d.Before(from) || d.After(today) {
				return
			}
			in = true
			perDay[d.Format("2006-01-02")] += secs
			st.TotalSeconds += secs
			g := perGame[s.GameID]
			if g == nil {
				g = &GameStat{ID: s.GameID, Title: s.Title, Launcher: s.Launcher}
				perGame[s.GameID] = g
			}
			g.Seconds += secs
		})
		if !in {
			continue
		}
		st.Sessions++
		g := perGame[s.GameID]
		g.Sessions++
		if lp := s.End.UTC().Format(time.RFC3339); lp > g.LastPlayed {
			g.LastPlayed = lp
			g.Title = s.Title // the newest title wins (launchers rename games)
		}
		if longest == nil || s.Seconds > longest.Seconds {
			c := s
			longest = &c
		}
	}
	pts := make([][2]float64, 0, days)
	for d := from; !d.After(today); d = d.AddDate(0, 0, 1) {
		k := d.Format("2006-01-02")
		st.PerDay = append(st.PerDay, DayStat{Date: k, Seconds: perDay[k]})
		if perDay[k] > 0 {
			st.DaysPlayed++
		}
		pts = append(pts, [2]float64{float64(d.Unix()), math.Round(float64(perDay[k])/36) / 100})
	}
	st.Series = []SeriesOut{{Name: "Hours played", Points: pts}}
	for _, g := range perGame {
		st.PerGame = append(st.PerGame, *g)
	}
	sort.Slice(st.PerGame, func(i, j int) bool {
		if st.PerGame[i].Seconds != st.PerGame[j].Seconds {
			return st.PerGame[i].Seconds > st.PerGame[j].Seconds
		}
		return st.PerGame[i].Title < st.PerGame[j].Title
	})
	st.Top = st.PerGame
	if len(st.Top) > 5 {
		st.Top = st.Top[:5]
	}
	if st.Sessions > 0 {
		st.AverageSession = st.TotalSeconds / int64(st.Sessions)
	}
	st.LongestSession = longest
	st.TotalHours = math.Round(float64(st.TotalSeconds)/36) / 100
	st.Streak = streaks(everDay, today)
	return st
}

// streaks finds the current run of days with play (ending today, or
// yesterday when today hasn't been played yet) and the longest run ever.
func streaks(days map[string]bool, today time.Time) Streak {
	var s Streak
	keys := make([]string, 0, len(days))
	for k := range days {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	run := 0
	var prev time.Time
	for _, k := range keys {
		d, _ := time.ParseInLocation("2006-01-02", k, today.Location())
		if run > 0 && sameDay(prev.AddDate(0, 0, 1), d) {
			run++
		} else {
			run = 1
		}
		if run > s.Longest {
			s.Longest = run
		}
		prev = d
	}
	d := today
	if !days[d.Format("2006-01-02")] {
		d = d.AddDate(0, 0, -1)
	}
	for days[d.Format("2006-01-02")] {
		s.Current++
		s.Since = d.Format("2006-01-02")
		d = d.AddDate(0, 0, -1)
	}
	return s
}

func sameDay(a, b time.Time) bool {
	return a.Year() == b.Year() && a.YearDay() == b.YearDay()
}
