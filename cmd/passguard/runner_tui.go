package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/Vashuus/passguard/internal/breach"
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

// ---- input component ----

// ---- model ----

type model struct {
	quit        bool
	pw          string
	show        bool
	force       strength.Result
	rep         breach.CheckReport
	checkBreach bool
	status      string
	leakProg    bool
	genProg     bool
	breach      *breach.Client
}

func initialModel(br *breach.Client) *model {
	m := &model{breach: br, show: true}
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
		case "ctrl+c", "esc":
			m.quit = true
			return m, tea.Quit
		case "q":
			m.quit = true
			return m, tea.Quit
		case "backspace":
			if len(m.pw) > 0 {
				m.pw = m.pw[:len(m.pw)-1]
			}
			m.recompute()
		case "enter":
			if m.checkBreach && !m.leakProg {
				m.leakProg = true
				m.status = "consultando filtraciones…"
				return m, leakCmd(m)
			}
		case " ":
			m.checkBreach = !m.checkBreach
			if !m.checkBreach {
				m.status = ""
			}
		case "g":
			if !m.genProg {
				m.genProg = true
				m.status = "generando…"
				return m, genCmd()
			}
		case "t", "r":
			m.show = !m.show
		}
	case leakResultMsg:
		m.leakProg = false
		m.rep = msg.rep
		if msg.err != nil {
			m.status = "error: " + msg.err.Error()
		} else if msg.rep.Found {
			m.status = fmt.Sprintf("¡Aparece en filtraciones (%d veces)!", msg.rep.Count)
		} else {
			m.status = "No aparece en filtraciones conocidas (HIBP)."
		}
	case genResultMsg:
		m.genProg = false
		if msg.err != nil {
			m.status = "error: " + msg.err.Error()
		} else {
			m.pw = msg.pw
			m.recompute()
			m.status = "Contraseña generada con CSPRNG."
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

func (m *model) View() string {
	if m.quit {
		return ""
	}
	var b strings.Builder
	b.WriteString(titleStyle.Render("🔐  PassGuard — Auditor de contraseñas\n"))

	// input field
	f := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#F5C2E7")).
		Padding(0, 1).
		Width(48)
	display := m.pw
	if !m.show && display != "" {
		display = strings.Repeat("•", len(display))
	}
	b.WriteString(f.Render(display) + "\n\n")

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
	b.WriteString("Fuerza   " + gaugeStyle.Render(gauge+" "+label(res.Score)) + "\n")
	b.WriteString(fmt.Sprintf("Entropía %.1f bits · Tiempo de crack (offline): %s\n", res.Entropy, res.CrackTime))

	if len(res.Patterns) > 0 {
		b.WriteString(dim.Render("Patrones: "))
		names := map[string]string{
			"dict":      "palabra común",
			"repeat":    "repetición",
			"seq_num":   "secuencia numérica",
			"seq_alpha": "secuencia alfabética",
			"seq_kbd":   "patrón de teclado",
			"keyboard":  "patrón de teclado",
		}
		parts := []string{}
		for _, p := range res.Patterns {
			n := names[p.Type]
			if n == "" {
				n = p.Type
			}
			parts = append(parts, fmt.Sprintf("%s(%q)", n, p.Token))
		}
		b.WriteString(strings.Join(parts, ", ") + "\n")
	}
	if res.Score < strength.ScoreSafelyUnguessable && res.Suggestions != nil {
		b.WriteString(yellow.Render(" » "+strings.Join(res.Suggestions, "\n  » ")) + "\n")
	}

	// breach block
	if m.checkBreach {
		if m.leakProg {
			b.WriteString(dim.Render("◆ consultando HIBP (k-anónimo)…\n"))
		} else if m.force.Score >= strength.ScoreSafelyUnguessable && m.rep.Hash != "" {
			if m.rep.Found {
				b.WriteString(red.Render("⚠ " + m.status + "\n"))
			} else {
				b.WriteString(green.Render("✓ " + m.status + "\n"))
			}
		} else {
			b.WriteString(dim.Render(" (pulsa Enter para consultar filtraciones)\n"))
		}
	} else {
		b.WriteString(dim.Render(" · Activá el chequeo HIBP con espacio (usa Enter)\n"))
	}

	// status + help
	if m.status != "" {
		b.WriteString(purple.Render("ℹ " + m.status + "\n"))
	}
	b.WriteString("\n" + dim.Render(
		"Teclas: espacio = HIBP  ·  g = generar  ·  t = mostrar/ocultar  ·  q/esc = salir"))

	return b.String()
}

// runTUI starts the interactive terminal interface.
func runTUI(ctx context.Context) error {
	_ = ctx
	prog := tea.NewProgram(initialModel(breach.New()), tea.WithAltScreen())
	_, err := prog.Run()
	return err
}
