package vbinui

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type Choice struct {
	Label   string
	Value   string
	Preview string
}

type SelectOptions struct {
	Title          string
	Query          string
	Index          int
	NonInteractive bool
	Input          io.Reader
	Output         io.Writer
}

type scoredChoice struct {
	choice Choice
	score  int
	order  int
}

func RankChoices(choices []Choice, query string) []Choice {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return append([]Choice(nil), choices...)
	}
	ranked := make([]scoredChoice, 0, len(choices))
	for index, choice := range choices {
		score, ok := fuzzyScore(strings.ToLower(choice.Label), query)
		if ok {
			ranked = append(ranked, scoredChoice{choice: choice, score: score, order: index})
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		return ranked[i].order < ranked[j].order
	})
	out := make([]Choice, len(ranked))
	for i := range ranked {
		out[i] = ranked[i].choice
	}
	return out
}

func fuzzyScore(value, query string) (int, bool) {
	if at := strings.Index(value, query); at >= 0 {
		return 10000 - at*20 - (len(value) - len(query)), true
	}
	position := 0
	score := 0
	last := -2
	for _, wanted := range query {
		found := -1
		for i, current := range value[position:] {
			if current == wanted {
				found = position + i
				break
			}
		}
		if found < 0 {
			return 0, false
		}
		score += 100 - found
		if found == last+1 {
			score += 40
		}
		last = found
		position = found + 1
	}
	return score, true
}

func SelectChoice(choices []Choice, options SelectOptions) (Choice, error) {
	filtered := RankChoices(choices, options.Query)
	if len(filtered) == 0 {
		return Choice{}, fmt.Errorf("pick: no matching choices")
	}
	if options.NonInteractive {
		if options.Index < 0 || options.Index >= len(filtered) {
			return Choice{}, fmt.Errorf("pick: index %d outside 0..%d", options.Index, len(filtered)-1)
		}
		return filtered[options.Index], nil
	}

	model := newPickerModel(choices, options)
	programOptions := []tea.ProgramOption{tea.WithAltScreen()}
	if options.Input != nil {
		programOptions = append(programOptions, tea.WithInput(options.Input))
	}
	if options.Output != nil {
		programOptions = append(programOptions, tea.WithOutput(options.Output))
	}
	result, err := tea.NewProgram(model, programOptions...).Run()
	if err != nil {
		return Choice{}, fmt.Errorf("pick: interactive UI: %w", err)
	}
	final := result.(pickerModel)
	if final.canceled {
		return Choice{}, fmt.Errorf("pick: canceled")
	}
	return final.selected, nil
}

type pickerModel struct {
	title    string
	all      []Choice
	visible  []Choice
	filter   textinput.Model
	cursor   int
	selected Choice
	canceled bool
	width    int
}

func newPickerModel(choices []Choice, options SelectOptions) pickerModel {
	filter := textinput.New()
	filter.Placeholder = "filter"
	filter.SetValue(options.Query)
	filter.Focus()
	return pickerModel{
		title:   options.Title,
		all:     append([]Choice(nil), choices...),
		visible: RankChoices(choices, options.Query),
		filter:  filter,
		cursor:  options.Index,
		width:   80,
	}
}

func (m pickerModel) Init() tea.Cmd { return textinput.Blink }

func (m pickerModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width = message.Width
	case tea.KeyMsg:
		switch message.String() {
		case "ctrl+c", "esc":
			m.canceled = true
			return m, tea.Quit
		case "up", "ctrl+p":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "ctrl+n":
			if m.cursor+1 < len(m.visible) {
				m.cursor++
			}
			return m, nil
		case "enter":
			if len(m.visible) > 0 {
				m.selected = m.visible[m.cursor]
				return m, tea.Quit
			}
		}
	}

	previous := m.filter.Value()
	var cmd tea.Cmd
	m.filter, cmd = m.filter.Update(message)
	if m.filter.Value() != previous {
		m.visible = RankChoices(m.all, m.filter.Value())
		m.cursor = 0
	}
	return m, cmd
}

func (m pickerModel) View() string {
	title := m.title
	if title == "" {
		title = "Select"
	}
	heading := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")).Render(title)
	var body strings.Builder
	for i, choice := range m.visible {
		prefix := "  "
		if i == m.cursor {
			prefix = "› "
		}
		body.WriteString(prefix)
		body.WriteString(choice.Label)
		body.WriteByte('\n')
	}
	preview := ""
	if len(m.visible) > 0 && m.cursor < len(m.visible) {
		preview = lipgloss.NewStyle().Faint(true).Width(max(20, m.width-4)).Render(m.visible[m.cursor].Preview)
	}
	return heading + "\n" + m.filter.View() + "\n\n" + body.String() + "\n" + preview + "\n"
}
