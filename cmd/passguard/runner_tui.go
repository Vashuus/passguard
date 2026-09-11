package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/Vashuus/passguard/internal/breach"
	"github.com/Vashuus/passguard/internal/clipboard"
	"github.com/Vashuus/passguard/internal/generator"
	"github.com/Vashuus/passguard/internal/strength"
	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ---- messages ----

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F5C2E7"))
	dim        = lipgloss.NewStyle().Foreground(lipgloss.Color("#6C7086"))
	green      = lipgloss.NewStyle().Foreground(lipgloss.Color("#A6E3A1"))
	red        = lipgloss.NewStyle().Foreground(lipgloss.Color("#F38BA8"))
	yellow     = lipgloss.NewStyle().Foreground(lipgloss.Color("#F9E2AF"))
	purple     = lipgloss.NewStyle().Foreground(lipgloss.Color("#CBA6F7"))
)

type leakResultMsg struct {
	rep breach.CheckReport
	err error
	pw  string
}

type genResultMsg struct {
	pw  string
	err error
}

type passResultMsg struct {
	pw  string
	err error
}

// ---- model ----

type model struct {
	quit     bool
	pw       string
	force    strength.Result
	rep      breach.CheckReport
	status   string
	leakProg bool
	genProg  bool
	passProg bool
	copyFn   func(string) error
	breach   *breach.Client
}

func initialModel(br *breach.Client) *model {
	m := &model{breach: br, copyFn: clipboard.Copy}
	m.recompute()
	return m
}

func (m *model) recompute() {
	m.force = strength.Estimate(m.pw)
}

func (m *model) Init() tea.Cmd { return nil }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type == tea.KeyRunes && len(msg.Runes) > 0 {
			r := msg.Runes[0]
			if r >= 32 && r <= 126 {
				m.pw += string(r)
				m.recompute()
			}
		}
		switch msg.String() {
		case "ctrl+c", "esc", "ctrl+q":
			m.quit = true
			return m, tea.Quit
		case "backspace":
			if len(m.pw) > 0 {
				m.pw = m.pw[:len(m.pw)-1]
			}
			m.recompute()
		case "enter":
			if m.pw != "" && !m.leakProg {
				m.leakProg = true
				m.status = "checking breaches…"
				return m, leakCmd(m)
			}
		case "ctrl+g":
			if !m.genProg {
				m.genProg = true
				m.status = "generating…"
				return m, genCmd()
			}
		case "ctrl+p":
			if !m.passProg {
				m.passProg = true
				m.status = "generating passphrase…"
				return m, passCmd()
			}
		case "ctrl+y":
			if m.pw == "" {
				m.status = "nothing to copy."
				break
			}
			if err := m.copyFn(m.pw); err != nil {
				m.status = "copy failed: " + err.Error()
			} else {
				m.status = "password copied to the clipboard."
			}
		}
	case leakResultMsg:
		m.leakProg = false
		m.rep = msg.rep
		if msg.err != nil {
			m.status = "error: " + msg.err.Error()
		} else if msg.rep.Found {
			m.status = fmt.Sprintf("Appears in breaches (%d times)!", msg.rep.Count)
		} else {
			m.status = "Not in known HIBP breaches."
		}
	case genResultMsg:
		m.genProg = false
		if msg.err != nil {
			m.status = "error: " + msg.err.Error()
		} else {
			m.pw = msg.pw
			m.recompute()
			m.status = "Password generated with the CSPRNG."
		}
	case passResultMsg:
		m.passProg = false
		if msg.err != nil {
			m.status = "error: " + msg.err.Error()
		} else {
			m.pw = msg.pw
			m.recompute()
			m.status = "Passphrase generated."
		}
	}
	return m, nil
}

func leakCmd(m *model) tea.Cmd {
	pw := m.pw
	return func() tea.Msg {
		rep, err := m.breach.Check(pw)
		return leakResultMsg{rep: rep, err: err, pw: pw}
	}
}

func genCmd() tea.Cmd {
	return func() tea.Msg {
		o := generator.DefaultOptions()
		pw, err := generator.Generate(o)
		return genResultMsg{pw: pw, err: err}
	}
}

func passCmd() tea.Cmd {
	return func() tea.Msg {
		pw, err := generator.GeneratePassphrase(4)
		return passResultMsg{pw: pw, err: err}
	}
}

func matchName(t string) string {
	names := map[string]string{
		"dict":      "dictionary word",
		"repeat":    "repetition",
		"seq_num":   "numeric sequence",
		"seq_alpha": "alphabetic sequence",
		"keyboard":  "keyboard pattern",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return t
}

func (m *model) View() string {
	if m.quit {
		return ""
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("🔐  PassGuard — Password auditor\n"))

	// input field
	f := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#F5C2E7")).
		Padding(0, 1).
		Width(48)
	b.WriteString(f.Render(m.pw) + "\n\n")

	// strength block
	res := m.force
	gauge := bar(res.Score)
	gaugeStyle := lipgloss.NewStyle().Bold(true)
	switch res.Score {
	case strength.ScoreTooGuessable, strength.ScoreVeryGuessable:
		gaugeStyle = gaugeStyle.Foreground(lipgloss.Color("#F38BA8"))
	case strength.ScoreSomewhatGuessable:
		gaugeStyle = gaugeStyle.Foreground(lipgloss.Color("#F9E2AF"))
	default:
		gaugeStyle = gaugeStyle.Foreground(lipgloss.Color("#A6E3A1"))
	}
	b.WriteString("Strength " + gaugeStyle.Render(gauge+" "+label(res.Score)) + "\n")
	b.WriteString(fmt.Sprintf("Entropy  %.1f bits · Crack time (fast offline): %s\n", res.Entropy, res.CrackTime))

	if len(res.Patterns) > 0 {
		b.WriteString(dim.Render("Patterns: "))
		parts := []string{}
		for _, p := range res.Patterns {
			parts = append(parts, fmt.Sprintf("%s(%q)", matchName(p.Type), p.Token))
		}
		b.WriteString(strings.Join(parts, ", ") + "\n")
	}
	if res.Score < strength.ScoreSafelyUnguessable && res.Suggestions != nil {
		b.WriteString(yellow.Render(" » "+strings.Join(res.Suggestions, "\n  » ")) + "\n")
	}

	// breach block
	if m.leakProg {
		b.WriteString(dim.Render("◆ checking HIBP (k-anonymous)…\n"))
	} else if m.pw == "" {
		b.WriteString(dim.Render(" · Type a password and press Enter to check breaches (HIBP)\n"))
	} else if m.rep.Hash == "" {
		b.WriteString(dim.Render(" · Enter = check breaches (HIBP, k-anonymous)\n"))
	} else if m.rep.Found {
		b.WriteString(red.Render("⚠ " + m.status + "\n"))
	} else {
		b.WriteString(green.Render("✓ " + m.status + "\n"))
	}

	// status + help
	if m.status != "" {
		b.WriteString(purple.Render("ℹ " + m.status + "\n"))
	}
	b.WriteString("\n" + dim.Render(
		"Ctrl+G generate   ·   Ctrl+P passphrase   ·   Ctrl+Y copy   ·   Enter HIBP   ·   Ctrl+Q/Esc quit"))

	return b.String()
}

// runTUI starts the interactive terminal interface.
func runTUI(ctx context.Context) error {
	_ = ctx
	prog := tea.NewProgram(initialModel(breach.New()), tea.WithAltScreen())
	_, err := prog.Run()
	return err
}
