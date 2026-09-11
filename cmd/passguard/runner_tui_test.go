package main

import (
	"testing"

	"github.com/Vashuus/passguard/internal/breach"
	"github.com/charmbracelet/bubbletea"
)

func newTestModel() *model {
	return initialModel(breach.New())
}

func kp(r rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
}

func TestTypingLettersNeverTriggersActions(t *testing.T) {
	m := newTestModel()
	for _, r := range []rune("gqtrabc 123") { // incluye antiguos hotkeys
		m.Update(kp(r))
	}
	if m.quit {
		t.Fatal("escribir letras no debe salir de la app")
	}
	if m.genProg || m.passProg || m.leakProg {
		t.Fatalf("escribir letras no debe disparar acciones: gen=%v pass=%v leak=%v", m.genProg, m.passProg, m.leakProg)
	}
	if m.pw != "gqtrabc 123" {
		t.Fatalf("input distorsionado: %q", m.pw)
	}
}

func TestCtrlKeysTriggerActions(t *testing.T) {
	m := newTestModel()
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlG})
	if !m.genProg || cmd == nil {
		t.Fatalf("ctrl+g debe generar (genProg=%v cmd=%v)", m.genProg, cmd != nil)
	}
	_, cmd = m.Update(tea.KeyMsg{Type: tea.KeyCtrlP})
	if !m.passProg || cmd == nil {
		t.Fatalf("ctrl+p debe generar frase-pase (passProg=%v cmd=%v)", m.passProg, cmd != nil)
	}
}

func TestEnterChecksBreachWithPassword(t *testing.T) {
	m := newTestModel()
	m.Update(kp('a'))
	m.Update(kp('b'))
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !m.leakProg || cmd == nil {
		t.Fatalf("enter con contraseña debe lanzar la consulta HIBP (leakProg=%v)", m.leakProg)
	}
}

func TestEnterWithoutPasswordDoesNothing(t *testing.T) {
	m := newTestModel()
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.leakProg || cmd != nil {
		t.Fatalf("enter sin contraseña no debe lanzar nada (leakProg=%v)", m.leakProg)
	}
}

func TestQuitKeys(t *testing.T) {
	for _, key := range []tea.KeyType{tea.KeyCtrlC, tea.KeyEsc, tea.KeyCtrlQ} {
		m := newTestModel()
		got, _ := m.Update(tea.KeyMsg{Type: key})
		if !got.(*model).quit {
			t.Fatalf("tecla %v debe salir", key)
		}
	}
}

func TestBackspaceRemovesLastRune(t *testing.T) {
	m := newTestModel()
	m.Update(kp('h'))
	m.Update(kp('i'))
	m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	if m.pw != "h" {
		t.Fatalf("backspace debe borrar el último carácter: %q", m.pw)
	}
}