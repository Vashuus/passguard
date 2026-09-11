package main

import (
	"strings"
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
	for _, r := range []rune("gqtrabc 123") { // includes the old single-letter hotkeys
		m.Update(kp(r))
	}
	if m.quit {
		t.Fatal("typing letters must not quit the app")
	}
	if m.genProg || m.passProg || m.leakProg {
		t.Fatalf("typing letters must not trigger actions: gen=%v pass=%v leak=%v", m.genProg, m.passProg, m.leakProg)
	}
	if m.pw != "gqtrabc 123" {
		t.Fatalf("input corrupted: %q", m.pw)
	}
}

func TestCtrlKeysTriggerActions(t *testing.T) {
	m := newTestModel()
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlG})
	if !m.genProg || cmd == nil {
		t.Fatalf("ctrl+g must generate (genProg=%v cmd=%v)", m.genProg, cmd != nil)
	}
	_, cmd = m.Update(tea.KeyMsg{Type: tea.KeyCtrlP})
	if !m.passProg || cmd == nil {
		t.Fatalf("ctrl+p must generate a passphrase (passProg=%v cmd=%v)", m.passProg, cmd != nil)
	}
}

func TestEnterChecksBreachWithPassword(t *testing.T) {
	m := newTestModel()
	m.Update(kp('a'))
	m.Update(kp('b'))
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !m.leakProg || cmd == nil {
		t.Fatalf("Enter with a password must run the HIBP query (leakProg=%v)", m.leakProg)
	}
}

func TestEnterWithoutPasswordDoesNothing(t *testing.T) {
	m := newTestModel()
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.leakProg || cmd != nil {
		t.Fatalf("Enter without a password must do nothing (leakProg=%v)", m.leakProg)
	}
}

func TestQuitKeys(t *testing.T) {
	for _, key := range []tea.KeyType{tea.KeyCtrlC, tea.KeyEsc, tea.KeyCtrlQ} {
		m := newTestModel()
		got, _ := m.Update(tea.KeyMsg{Type: key})
		if !got.(*model).quit {
			t.Fatalf("key %v must quit", key)
		}
	}
}

func TestCopyKeyCopiesPassword(t *testing.T) {
	m := newTestModel()
	var copied string
	m.copyFn = func(s string) error { copied = s; return nil }
	m.Update(kp('h'))
	m.Update(kp('i'))
	m.Update(tea.KeyMsg{Type: tea.KeyCtrlY})
	if copied != "hi" {
		t.Fatalf("ctrl+y must copy the typed password, got %q", copied)
	}
	if !strings.Contains(m.status, "copied") {
		t.Fatalf("status should confirm the copy, got %q", m.status)
	}
}

func TestBackspaceRemovesLastRune(t *testing.T) {
	m := newTestModel()
	m.Update(kp('h'))
	m.Update(kp('i'))
	m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	if m.pw != "h" {
		t.Fatalf("backspace must remove the last rune: %q", m.pw)
	}
}
