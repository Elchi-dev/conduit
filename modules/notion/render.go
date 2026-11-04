package notion

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/elchi-dev/conduit/pkg/sdk"
)

type blockBody struct {
	RichText   []richText   `json:"rich_text"`
	Checked    bool         `json:"checked"`
	Language   string       `json:"language"`
	Caption    []richText   `json:"caption"`
	URL        string       `json:"url"`
	Title      string       `json:"title"`
	Expression string       `json:"expression"`
	Cells      [][]richText `json:"cells"`
	External   *struct {
		URL string `json:"url"`
	} `json:"external"`
	Name string `json:"name"`
	Icon *struct {
		Emoji string `json:"emoji"`
	} `json:"icon"`
}

type block struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	HasChildren bool   `json:"has_children"`
	InTrash     bool   `json:"in_trash"`
	body        blockBody
}

func (b *block) UnmarshalJSON(raw []byte) error {
	type plainBlock block
	var pb plainBlock
	if err := json.Unmarshal(raw, &pb); err != nil {
		return err
	}
	*b = block(pb)
	var all map[string]json.RawMessage
	if json.Unmarshal(raw, &all) == nil && b.Type != "" {
		_ = json.Unmarshal(all[b.Type], &b.body)
	}
	return nil
}

func (b block) text() string {
	switch {
	case len(b.body.RichText) > 0:
		return plain(b.body.RichText)
	case b.body.Title != "":
		return b.body.Title
	case b.body.URL != "":
		return b.body.URL
	}
	return ""
}

// md renders rich text as Markdown.
func md(rt []richText) string {
	var b strings.Builder
	for _, r := range rt {
		t := r.PlainText
		if strings.TrimSpace(t) != "" {
			a := r.Annotations
			switch {
			case a.Code:
				t = "`" + t + "`"
			default:
				if a.Bold {
					t = "**" + t + "**"
				}
				if a.Italic {
					t = "*" + t + "*"
				}
				if a.Strikethrough {
					t = "~~" + t + "~~"
				}
			}
			if r.Href != "" && (strings.HasPrefix(r.Href, "https://") || strings.HasPrefix(r.Href, "http://") || strings.HasPrefix(r.Href, "/")) {
				t = "[" + t + "](" + r.Href + ")"
			}
		}
		b.WriteString(t)
	}
	return b.String()
}

type walker struct {
	c        *conn
	ctx      context.Context
	maxDepth int
	maxChars int
	requests int
	blocks   int
	out      strings.Builder
	cut      bool
}

func (w *walker) full() bool { return w.cut || w.out.Len() >= w.maxChars }

func (w *walker) children(id string) ([]block, error) {
	var all []block
	q := url.Values{"page_size": {"100"}}
	for {
		if w.requests >= maxPageRequests {
			w.cut = true
			return all, nil
		}
		w.requests++
		var res struct {
			Results    []block `json:"results"`
			HasMore    bool    `json:"has_more"`
			NextCursor *string `json:"next_cursor"`
		}
		if _, err := w.c.api.Do(w.ctx, http.MethodGet, "/blocks/"+id+"/children", q, nil, &res); err != nil {
			return all, err
		}
		all = append(all, res.Results...)
		if !res.HasMore || res.NextCursor == nil {
			return all, nil
		}
		q.Set("start_cursor", *res.NextCursor)
	}
}

func (w *walker) line(indent, s string) {
	if w.full() {
		w.cut = true
		return
	}
	w.out.WriteString(indent + s + "\n")
}

// walk renders the children of id at a depth (0 for the page itself).
func (w *walker) walk(id string, depth int, indent string) error {
	bs, err := w.children(id)
	if err != nil {
		return err
	}
	num := 0
	for _, b := range bs {
		if w.full() {
			w.cut = true
			return nil
		}
		if _, err := normID(b.ID, "block"); err != nil {
			continue // never put an odd id into a path
		}
		w.blocks++
		if b.Type == "numbered_list_item" {
			num++
		} else {
			num = 0
		}
		t := md(b.body.RichText)
		childIndent := indent
		switch b.Type {
		case "paragraph":
			w.line(indent, t)
		case "heading_1", "heading_2", "heading_3":
			w.line(indent, strings.Repeat("#", int(b.Type[len(b.Type)-1]-'0'))+" "+t)
		case "bulleted_list_item":
			w.line(indent, "- "+t)
			childIndent += "  "
		case "numbered_list_item":
			w.line(indent, fmt.Sprintf("%d. %s", num, t))
			childIndent += "   "
		case "to_do":
			box := "[ ]"
			if b.body.Checked {
				box = "[x]"
			}
			w.line(indent, "- "+box+" "+t)
			childIndent += "  "
		case "toggle":
			w.line(indent, "- "+t)
			childIndent += "  "
		case "quote":
			w.line(indent, "> "+t)
			childIndent += "> "
		case "callout":
			icon := ""
			if b.body.Icon != nil && b.body.Icon.Emoji != "" {
				icon = b.body.Icon.Emoji + " "
			}
			w.line(indent, "> "+icon+t)
			childIndent += "> "
		case "code":
			w.line(indent, "```"+b.body.Language)
			for _, l := range strings.Split(plain(b.body.RichText), "\n") {
				w.line(indent, l)
			}
			w.line(indent, "```")
		case "equation":
			w.line(indent, "$$"+b.body.Expression+"$$")
		case "divider":
			w.line(indent, "---")
		case "child_page":
			w.line(indent, fmt.Sprintf("[page: %s] (%s)", b.body.Title, b.ID))
			continue // a sub-page is read on its own
		case "child_database":
			w.line(indent, fmt.Sprintf("[database: %s] (%s)", b.body.Title, b.ID))
			continue
		case "bookmark", "embed", "link_preview":
			w.line(indent, fmt.Sprintf("[%s](%s)", firstNonEmpty(md(b.body.Caption), b.body.URL), b.body.URL))
		case "image", "video", "file", "pdf", "audio":
			// Notion-hosted files come with short-lived signed links;
			// only external links are worth returning.
			label := firstNonEmpty(md(b.body.Caption), b.body.Name, b.Type)
			if b.body.External != nil && b.body.External.URL != "" {
				w.line(indent, fmt.Sprintf("[%s: %s](%s)", b.Type, label, b.body.External.URL))
			} else {
				w.line(indent, fmt.Sprintf("[%s: %s]", b.Type, label))
			}
		case "table":
			if depth+1 <= w.maxDepth && b.HasChildren {
				rows, err := w.children(b.ID)
				if err != nil {
					return err
				}
				for i, r := range rows {
					cells := []string{}
					for _, c := range r.body.Cells {
						cells = append(cells, strings.ReplaceAll(md(c), "|", `\|`))
					}
					w.line(indent, "| "+strings.Join(cells, " | ")+" |")
					if i == 0 {
						w.line(indent, strings.Repeat("| --- ", len(cells))+"|")
					}
				}
			}
			continue
		case "column_list", "column", "synced_block", "template":
			// Containers: their children carry the content.
		case "link_to_page":
			w.line(indent, "[link to page]")
		case "table_of_contents", "breadcrumb":
			continue
		default:
			if t != "" {
				w.line(indent, t)
			} else {
				w.line(indent, "["+b.Type+"]")
			}
		}
		if b.HasChildren {
			if depth+1 >= w.maxDepth {
				w.line(childIndent, "…")
				continue
			}
			if err := w.walk(b.ID, depth+1, childIndent); err != nil {
				return err
			}
		}
	}
	return nil
}

func firstNonEmpty(s ...string) string {
	for _, x := range s {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}

func (c *conn) readPage(ctx context.Context, p input) (sdk.Result, error) {
	pg, err := c.getPage(ctx, p.Page)
	if err != nil {
		return sdk.Result{}, err
	}
	maxChars := p.MaxChars
	if maxChars <= 0 || maxChars > 200000 {
		maxChars = 20000
	}
	depth := p.Depth
	if depth <= 0 || depth > 5 {
		depth = 3
	}
	w := &walker{c: c, ctx: ctx, maxDepth: depth, maxChars: maxChars}
	if err := w.walk(pg.ID, 0, ""); err != nil {
		return sdk.Result{}, err
	}
	text := w.out.String()
	if r := []rune(text); len(r) > maxChars {
		text, w.cut = string(r[:maxChars]), true
	}
	out := pageSummary(pg, true)
	out["markdown"] = strings.TrimRight(text, "\n")
	out["blocks"] = w.blocks
	out["truncated"] = w.cut
	return sdk.JSON(out)
}
