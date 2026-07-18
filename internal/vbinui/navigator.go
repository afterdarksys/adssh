package vbinui

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type FileEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"is_dir"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
}

func ListDirectory(path string, showHidden bool) ([]FileEntry, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("nav: read %s: %w", path, err)
	}
	out := make([]FileEntry, 0, len(entries))
	for _, entry := range entries {
		if !showHidden && strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		out = append(out, FileEntry{
			Name:  entry.Name(),
			Path:  filepath.Join(path, entry.Name()),
			IsDir: entry.IsDir(),
			Size:  info.Size(),
			Mode:  info.Mode().String(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

func PreviewPath(path string, maxBytes int) (string, error) {
	if maxBytes <= 0 {
		maxBytes = 32 * 1024
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("nav: preview %s: %w", path, err)
	}
	if info.IsDir() {
		entries, err := ListDirectory(path, true)
		if err != nil {
			return "", err
		}
		var builder strings.Builder
		for _, entry := range entries {
			name := entry.Name
			if entry.IsDir {
				name += "/"
			}
			if builder.Len()+len(name)+1 > maxBytes {
				builder.WriteString("… (truncated)")
				break
			}
			builder.WriteString(name)
			builder.WriteByte('\n')
		}
		return strings.TrimSuffix(builder.String(), "\n"), nil
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("nav: preview %s: %w", path, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes+1)))
	if err != nil {
		return "", fmt.Errorf("nav: preview %s: %w", path, err)
	}
	truncated := len(data) > maxBytes
	if truncated {
		data = data[:maxBytes]
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return fmt.Sprintf("Binary file · %d bytes", info.Size()), nil
	}
	text := string(data)
	if truncated {
		text += "\n… (truncated)"
	}
	return text, nil
}

type NavigateOptions struct {
	ShowHidden bool
	Input      io.Reader
	Output     io.Writer
}

func Navigate(root string, options NavigateOptions) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("nav: resolve path: %w", err)
	}
	model, err := newNavigatorModel(abs, options.ShowHidden)
	if err != nil {
		return "", err
	}
	programOptions := []tea.ProgramOption{tea.WithAltScreen()}
	if options.Input != nil {
		programOptions = append(programOptions, tea.WithInput(options.Input))
	}
	if options.Output != nil {
		programOptions = append(programOptions, tea.WithOutput(options.Output))
	}
	result, err := tea.NewProgram(model, programOptions...).Run()
	if err != nil {
		return "", fmt.Errorf("nav: interactive UI: %w", err)
	}
	final := result.(navigatorModel)
	if final.canceled {
		return "", fmt.Errorf("nav: canceled")
	}
	return final.selected, nil
}

type navigatorModel struct {
	dir        string
	entries    []FileEntry
	cursor     int
	showHidden bool
	selected   string
	canceled   bool
	err        error
	width      int
	height     int
}

func newNavigatorModel(dir string, showHidden bool) (navigatorModel, error) {
	entries, err := ListDirectory(dir, showHidden)
	if err != nil {
		return navigatorModel{}, err
	}
	return navigatorModel{dir: dir, entries: entries, showHidden: showHidden, width: 120, height: 30}, nil
}

func (m navigatorModel) Init() tea.Cmd { return nil }

func (m navigatorModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = message.Width, message.Height
	case tea.KeyMsg:
		switch message.String() {
		case "ctrl+c", "esc", "q":
			m.canceled = true
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor+1 < len(m.entries) {
				m.cursor++
			}
		case "left", "h", "backspace":
			m = m.changeDir(filepath.Dir(m.dir))
		case ".":
			m.showHidden = !m.showHidden
			m = m.changeDir(m.dir)
		case "right", "l", "enter":
			if len(m.entries) == 0 {
				break
			}
			entry := m.entries[m.cursor]
			if entry.IsDir {
				m = m.changeDir(entry.Path)
			} else {
				m.selected = entry.Path
				return m, tea.Quit
			}
		case "c":
			m.selected = m.dir
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m navigatorModel) changeDir(path string) navigatorModel {
	entries, err := ListDirectory(path, m.showHidden)
	if err != nil {
		m.err = err
		return m
	}
	m.dir, m.entries, m.cursor, m.err = path, entries, 0, nil
	return m
}

func (m navigatorModel) View() string {
	columnWidth := max(20, (m.width-8)/3)
	parent := m.parentView()
	current := m.currentView()
	preview := ""
	if len(m.entries) > 0 {
		preview, _ = PreviewPath(m.entries[m.cursor].Path, max(1024, columnWidth*max(10, m.height-5)))
	}
	box := lipgloss.NewStyle().Width(columnWidth).Height(max(8, m.height-4)).Padding(0, 1).Border(lipgloss.RoundedBorder())
	header := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")).Render("nav · " + m.dir)
	footer := lipgloss.NewStyle().Faint(true).Render("↑↓ move · ← parent · →/enter open · c choose directory · . hidden · q quit")
	columns := lipgloss.JoinHorizontal(lipgloss.Top,
		box.Render(parent), box.Render(current), box.Render(preview),
	)
	if m.err != nil {
		footer = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render(m.err.Error())
	}
	return header + "\n" + columns + "\n" + footer + "\n"
}

func (m navigatorModel) parentView() string {
	parent := filepath.Dir(m.dir)
	entries, err := ListDirectory(parent, m.showHidden)
	if err != nil {
		return err.Error()
	}
	var lines []string
	currentName := filepath.Base(m.dir)
	for _, entry := range entries {
		prefix := "  "
		if entry.Name == currentName {
			prefix = "› "
		}
		lines = append(lines, prefix+entry.Name)
	}
	return strings.Join(lines, "\n")
}

func (m navigatorModel) currentView() string {
	var lines []string
	for index, entry := range m.entries {
		prefix := "  "
		if index == m.cursor {
			prefix = "› "
		}
		name := entry.Name
		if entry.IsDir {
			name += "/"
		}
		lines = append(lines, prefix+name)
	}
	return strings.Join(lines, "\n")
}
