package standards

// Starter standards, written once into an empty library. They are generic on
// purpose: the owner edits them into their own. Deleted starters don't come
// back (a .seeded marker records that seeding happened).

func seedStandards() []Standard {
	return []Standard{
		{
			ID: "frontend-design", Title: "Frontend design principles", Icon: "palette", Category: "frontend",
			Summary:   "How interfaces built for me should look and feel: intentional, calm, consistent and fast.",
			Tags:      []string{"ui", "design", "css"},
			AppliesTo: []string{"frontend", "design", "*.tsx", "*.jsx", "*.vue", "*.svelte", "*.css", "*.html"},
			Priority:  70, Enabled: true,
			Sections: []Section{
				{Kind: "principles", Items: []string{
					"Start from the content and the task, not from a component library's defaults.",
					"One clear primary action per screen; everything else steps back.",
					"Use the project's existing design tokens before inventing new values.",
					"Consistency beats novelty: the same thing looks and behaves the same everywhere.",
					"Every state is designed: empty, loading, error, partial and full.",
				}},
				{Kind: "dodont", Pairs: []Pair{
					{Do: "Build hierarchy with size, weight and spacing", Dont: "Reach for borders, shadows and colour first"},
					{Do: "Use a spacing scale (4 / 8 / 12 / 16 / 24 / 32 …)", Dont: "Use arbitrary one-off margins like 13px"},
					{Do: "Left-align text and keep lines to 60–80 characters", Dont: "Centre long paragraphs"},
					{Do: "Write empty states that say what to do next", Dont: "Show a blank area or just \"No data\""},
					{Do: "Support dark and light schemes through tokens", Dont: "Hard-code hex values in components"},
				}},
				{Kind: "rules", Rules: []Rule{
					{Level: "must", Text: "Layouts work from 320 px wide up without horizontal scrolling.", Why: "Phones are a first-class screen."},
					{Level: "must", Text: "Colours, spacing, radii and type sizes come from design tokens.", Why: "Theming and consistency depend on it."},
					{Level: "should", Text: "Keep motion under 200 ms and purposeful; respect prefers-reduced-motion."},
					{Level: "should", Text: "Prefer system or already-loaded fonts; at most two families."},
					{Level: "may", Text: "Add one signature detail per product, used sparingly."},
				}},
				{Kind: "examples", Examples: []Example{
					{Title: "Tokens, not literals", Lang: "css",
						Good: ".card {\n  padding: var(--space-4);\n  border-radius: var(--radius-md);\n  color: var(--ink);\n}",
						Bad:  ".card {\n  padding: 13px;\n  border-radius: 7px;\n  color: #333;\n}"},
				}},
				{Kind: "tokens", Groups: []TokenGroup{
					{Name: "Colours", Kind: "color", Tokens: []Token{
						{Key: "ink", Value: "#1e2328", Note: "body text"},
						{Key: "muted", Value: "#5b6570", Note: "secondary text"},
						{Key: "surface", Value: "#ffffff"},
						{Key: "page", Value: "#eef0f2"},
						{Key: "accent", Value: "#3d6bd8", Note: "links, primary buttons"},
						{Key: "danger", Value: "#c23a32"},
					}},
					{Name: "Type scale", Kind: "type", Tokens: []Token{
						{Key: "display", Value: "32px / 1.15 / 650"},
						{Key: "title", Value: "22px / 1.25 / 600"},
						{Key: "body", Value: "15px / 1.5 / 400"},
						{Key: "small", Value: "13px / 1.4 / 400"},
					}},
					{Name: "Spacing", Kind: "spacing", Tokens: []Token{
						{Key: "space-1", Value: "4px"}, {Key: "space-2", Value: "8px"}, {Key: "space-3", Value: "12px"},
						{Key: "space-4", Value: "16px"}, {Key: "space-6", Value: "24px"}, {Key: "space-8", Value: "32px"},
					}},
				}},
				{Kind: "checklist", Items: []string{
					"Checked at 320 px, 768 px and 1280 px",
					"Checked in dark and light mode",
					"Empty, loading and error states exist",
					"No hard-coded colours or spacing",
				}},
			},
		},
		{
			ID: "accessibility", Title: "Accessibility (WCAG 2.2 AA essentials)", Icon: "eye", Category: "frontend",
			Summary:   "The accessibility floor for anything with a user interface. Not optional.",
			Tags:      []string{"a11y", "wcag"},
			AppliesTo: []string{"frontend", "accessibility", "*.tsx", "*.jsx", "*.vue", "*.svelte", "*.html"},
			Priority:  90, Enabled: true,
			Sections: []Section{
				{Kind: "rules", Rules: []Rule{
					{Level: "must", Text: "Text contrast is at least 4.5:1 (3:1 for large text and for UI parts and focus indicators).", Why: "WCAG 1.4.3 and 1.4.11."},
					{Level: "must", Text: "Everything works with the keyboard alone, in a logical order, with no traps.", Why: "WCAG 2.1.1, 2.1.2, 2.4.3."},
					{Level: "must", Text: "Focus is always visible and never hidden behind sticky headers or overlays.", Why: "WCAG 2.4.7 and 2.4.11 (new in 2.2)."},
					{Level: "must", Text: "Every control has an accessible name; icon-only buttons get aria-label.", Why: "WCAG 4.1.2."},
					{Level: "must", Text: "Form fields have visible labels, and errors say what is wrong and how to fix it.", Why: "WCAG 3.3.1, 3.3.2, 3.3.3."},
					{Level: "must", Text: "Pointer targets are at least 24 × 24 CSS px, or spaced so they don't overlap.", Why: "WCAG 2.5.8 (new in 2.2)."},
					{Level: "must", Text: "Anything done by dragging also works with a single click or tap.", Why: "WCAG 2.5.7 (new in 2.2)."},
					{Level: "must", Text: "Images that carry meaning have alt text; decorative ones have alt=\"\".", Why: "WCAG 1.1.1."},
					{Level: "should", Text: "Use native elements (button, a, label, dialog) before ARIA roles."},
					{Level: "should", Text: "Don't make people re-enter information they already gave in the same flow.", Why: "WCAG 3.3.7 (new in 2.2)."},
					{Level: "should", Text: "Sign-in doesn't depend on memorising or transcribing; allow paste and password managers.", Why: "WCAG 3.3.8 (new in 2.2)."},
				}},
				{Kind: "dodont", Pairs: []Pair{
					{Do: "<button> for actions, <a href> for navigation", Dont: "<div onClick> for either"},
					{Do: "Convey state with text or icons as well as colour", Dont: "Rely on red and green alone"},
					{Do: "Announce async results with a live region", Dont: "Change content silently"},
				}},
				{Kind: "examples", Examples: []Example{
					{Title: "Icon button", Lang: "tsx",
						Good: "<button type=\"button\" aria-label=\"Close dialog\" onClick={close}>\n  <XIcon aria-hidden />\n</button>",
						Bad:  "<div className=\"icon\" onClick={close}>\n  <XIcon />\n</div>"},
				}},
				{Kind: "checklist", Items: []string{
					"Tab through the whole page: order is logical and focus is visible",
					"Zoom to 200 % and 400 %: nothing is cut off",
					"Run axe or Lighthouse: no serious or critical issues",
					"Check with a screen reader for headings, labels and live updates",
					"prefers-reduced-motion turns off non-essential animation",
				}},
				{Kind: "references", Links: []Link{
					{Title: "WCAG 2.2", URL: "https://www.w3.org/TR/WCAG22/"},
					{Title: "What's new in WCAG 2.2", URL: "https://www.w3.org/WAI/standards-guidelines/wcag/new-in-22/"},
					{Title: "ARIA Authoring Practices Guide", URL: "https://www.w3.org/WAI/ARIA/apg/"},
				}},
			},
		},
		{
			ID: "ui-writing", Title: "Writing for UI", Icon: "pen", Category: "writing",
			Summary:   "Interface text and short-form writing: plain, specific and kind.",
			Tags:      []string{"copy", "microcopy", "tone"},
			AppliesTo: []string{"writing", "frontend", "email"},
			Priority:  60, Enabled: true,
			Sections: []Section{
				{Kind: "principles", Items: []string{
					"Say what happens, in the words people use.",
					"Front-load the important part; people scan.",
					"Be specific: numbers, names and next steps beat adjectives.",
					"Calm and direct, never cute at the expense of clarity.",
				}},
				{Kind: "rules", Rules: []Rule{
					{Level: "must", Text: "Buttons say exactly what they do (\"Delete project\", not \"OK\")."},
					{Level: "must", Text: "Error messages say what went wrong and what to do next, without blame."},
					{Level: "should", Text: "Sentence case for headings, labels and buttons."},
					{Level: "should", Text: "Keep sentences under about 20 words; one idea per sentence."},
					{Level: "should", Text: "Use active voice and address the reader as \"you\"."},
					{Level: "may", Text: "Use light humour in empty states and success messages, never in errors."},
				}},
				{Kind: "dodont", Pairs: []Pair{
					{Do: "Couldn't save. Check your connection and try again.", Dont: "Error 500: An unexpected error has occurred."},
					{Do: "3 files uploaded", Dont: "Upload process completed successfully!"},
					{Do: "Remove", Dont: "Click here to remove this item"},
				}},
				{Kind: "examples", Examples: []Example{
					{Title: "Confirmation dialog",
						Good: "Delete \"Q3 report\"?\nIt will be gone for everyone. This can't be undone.\n[Delete report] [Cancel]",
						Bad:  "Are you sure?\nThis action is irreversible.\n[OK] [Cancel]"},
				}},
				{Kind: "checklist", Items: []string{
					"Every button is a verb that names the outcome",
					"No jargon, internal names or error codes without an explanation",
					"Read it aloud: does it sound like a person?",
				}},
			},
		},
		{
			ID: "git-commits", Title: "Git commit messages", Icon: "git", Category: "git",
			Summary:   "Commits that explain themselves: Conventional Commits with a useful body.",
			Tags:      []string{"git", "conventional-commits"},
			AppliesTo: []string{"git", "**/COMMIT_EDITMSG"},
			Priority:  60, Enabled: true,
			Sections: []Section{
				{Kind: "rules", Rules: []Rule{
					{Level: "must", Text: "Subject follows Conventional Commits: type(scope): summary, with type one of feat, fix, docs, refactor, perf, test, build, ci, chore.", Why: "Changelogs and release tooling read it."},
					{Level: "must", Text: "Subject is imperative, lower case after the colon, no trailing full stop, 72 characters at most."},
					{Level: "must", Text: "Never commit secrets, generated credentials or personal data."},
					{Level: "must", Text: "Breaking changes say so: an ! after the type and a BREAKING CHANGE: footer."},
					{Level: "should", Text: "The body explains why the change was made and what it affects, wrapped at 72 columns."},
					{Level: "should", Text: "One logical change per commit; formatting-only changes go in their own commit."},
					{Level: "should", Text: "Reference issues in a footer (Fixes #123)."},
					{Level: "may", Text: "Use a scope when the repository has clear areas (web, api, docs)."},
				}},
				{Kind: "examples", Examples: []Example{
					{Title: "A good commit",
						Good: "fix(auth): keep sessions alive across daemon restarts\n\nSessions were stored in memory only, so every restart signed\neveryone out. Store them in the database and prune expired\nones hourly.\n\nFixes #241",
						Bad:  "Fixed stuff."},
				}},
				{Kind: "dodont", Pairs: []Pair{
					{Do: "feat(web): add dark mode toggle", Dont: "Added dark mode toggle and fixed some bugs and cleanup"},
					{Do: "Split unrelated changes into separate commits", Dont: "Bundle a refactor with a bug fix"},
				}},
				{Kind: "references", Links: []Link{{Title: "Conventional Commits 1.0.0", URL: "https://www.conventionalcommits.org/en/v1.0.0/"}}},
			},
		},
		{
			ID: "code-review", Title: "Code review checklist", Icon: "check", Category: "review",
			Summary:   "What to look for when reviewing a change, in order of importance.",
			Tags:      []string{"review", "pr"},
			AppliesTo: []string{"review"},
			Priority:  65, Enabled: true,
			Sections: []Section{
				{Kind: "principles", Items: []string{
					"Correctness and safety first, then design, then style.",
					"Review the change, not the person; suggest, explain, and say what's good too.",
					"Small, focused changes get better reviews: ask to split large ones.",
				}},
				{Kind: "checklist", Items: []string{
					"Does it do what the description says, and is the description clear?",
					"Edge cases: empty, huge, concurrent, failing network, bad input",
					"Errors are handled, surfaced and not swallowed",
					"No secrets, injection (SQL, shell, HTML), path traversal or missing authorisation checks",
					"Tests cover the change, including the failure path",
					"Names, structure and comments make the next change easy",
					"No unrelated changes, dead code or debug output",
					"Docs, changelog and migrations are updated where needed",
					"Performance: no N+1 queries, unbounded loops or loading everything into memory",
				}},
				{Kind: "rules", Rules: []Rule{
					{Level: "must", Text: "Mark each comment as blocking or a suggestion (prefix nit: for small things)."},
					{Level: "should", Text: "Explain why a change is needed and propose a concrete alternative."},
					{Level: "should", Text: "Summarise the review in a sentence: approve, approve with nits, or what must change."},
				}},
			},
		},
	}
}

func seedToolkits() []Toolkit {
	return []Toolkit{
		{ID: "frontend-kit", Title: "Frontend kit", Icon: "layers", Summary: "Design, accessibility and UI writing for anything with a screen.",
			Standards: []string{"frontend-design", "accessibility", "ui-writing"}},
		{ID: "shipping-kit", Title: "Shipping kit", Icon: "rocket", Summary: "Reviewing and committing changes.",
			Standards: []string{"code-review", "git-commits"}},
	}
}
