package security

import (
	"sort"
	"strings"
)

// HelpEntry is one topic in the help system.
type HelpEntry struct {
	Name        string
	Category    string // "vbin", "builtin", "starlark", "concept", "security"
	Summary     string // one line, shown in listings
	Description string // full description, multiple paragraphs OK
	Usage       string // usage string(s)
	Examples    []HelpExample
	SeeAlso     []string
	Tags        []string // searchable keywords
}

// HelpExample is a single usage example within a HelpEntry.
type HelpExample struct {
	Command     string
	Description string
}

var helpEntries []HelpEntry

// RegisterHelp appends a help entry to the registry.
// If an entry with the same name already exists it is replaced.
func RegisterHelp(e HelpEntry) {
	for i, existing := range helpEntries {
		if strings.EqualFold(existing.Name, e.Name) {
			helpEntries[i] = e
			return
		}
	}
	helpEntries = append(helpEntries, e)
}

// AllHelpEntries returns a copy of all registered help entries.
func AllHelpEntries() []HelpEntry {
	out := make([]HelpEntry, len(helpEntries))
	copy(out, helpEntries)
	return out
}

// GetHelp returns the help entry for an exact name match (case-insensitive).
func GetHelp(name string) (*HelpEntry, bool) {
	lc := strings.ToLower(name)
	for i, e := range helpEntries {
		if strings.ToLower(e.Name) == lc {
			cp := helpEntries[i]
			return &cp, true
		}
	}
	return nil, false
}

// SearchHelp performs a ranked, case-insensitive search across Name, Summary,
// Description, Tags, and Examples. Returns deduplicated, sorted results.
//
// Ranking: name match (3 pts) > tag match (2 pts) > body match (1 pt).
func SearchHelp(query string) []HelpEntry {
	lq := strings.ToLower(query)

	type scored struct {
		entry HelpEntry
		score int
	}
	var results []scored

	for _, e := range helpEntries {
		score := 0

		if strings.Contains(strings.ToLower(e.Name), lq) {
			score += 3
		}
		for _, t := range e.Tags {
			if strings.Contains(strings.ToLower(t), lq) {
				score += 2
				break
			}
		}
		if score == 0 {
			if strings.Contains(strings.ToLower(e.Summary), lq) ||
				strings.Contains(strings.ToLower(e.Description), lq) {
				score += 1
			}
		}
		for _, ex := range e.Examples {
			if strings.Contains(strings.ToLower(ex.Command), lq) ||
				strings.Contains(strings.ToLower(ex.Description), lq) {
				if score == 0 {
					score = 1
				}
				break
			}
		}

		if score > 0 {
			results = append(results, scored{entry: e, score: score})
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].score != results[j].score {
			return results[i].score > results[j].score
		}
		return results[i].entry.Name < results[j].entry.Name
	})

	out := make([]HelpEntry, len(results))
	for i, r := range results {
		out[i] = r.entry
	}
	return out
}

// HelpCategories returns a unique, sorted list of all categories in the registry.
func HelpCategories() []string {
	seen := map[string]bool{}
	for _, e := range helpEntries {
		seen[e.Category] = true
	}
	cats := make([]string, 0, len(seen))
	for c := range seen {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	return cats
}

// HelpByCategory returns all entries whose Category matches cat (case-insensitive).
func HelpByCategory(cat string) []HelpEntry {
	lc := strings.ToLower(cat)
	var out []HelpEntry
	for _, e := range helpEntries {
		if strings.ToLower(e.Category) == lc {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// PopulateVBINHelp iterates ListVBins() and registers a help entry for each VBIN
// that does not already have one. Called on every help invocation so dynamically
// registered VBINs are always included.
func PopulateVBINHelp() {
	for _, vb := range ListVBins() {
		if _, exists := GetHelp(vb.Name()); exists {
			continue
		}
		RegisterHelp(HelpEntry{
			Name:     vb.Name(),
			Category: "vbin",
			Summary:  vb.Description(),
			Usage:    vb.Usage(),
			Tags:     []string{vb.Name(), "vbin"},
		})
	}
}

// wordWrap wraps text at width characters, preserving existing newlines.
func wordWrap(text string, width int) string {
	if width <= 0 {
		width = 80
	}
	var sb strings.Builder
	paragraphs := strings.Split(text, "\n")
	for pi, para := range paragraphs {
		if para == "" {
			sb.WriteByte('\n')
			continue
		}
		words := strings.Fields(para)
		lineLen := 0
		for i, w := range words {
			wl := len(w)
			if lineLen == 0 {
				sb.WriteString(w)
				lineLen = wl
			} else if lineLen+1+wl > width {
				sb.WriteByte('\n')
				sb.WriteString(w)
				lineLen = wl
			} else {
				sb.WriteByte(' ')
				sb.WriteString(w)
				lineLen += 1 + wl
			}
			_ = i
		}
		if pi < len(paragraphs)-1 {
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}
