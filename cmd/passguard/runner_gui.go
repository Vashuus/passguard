package main

import (
	"context"
	"fmt"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/Vashuus/passguard/internal/breach"
	"github.com/Vashuus/passguard/internal/generator"
	"github.com/Vashuus/passguard/internal/strength"
)

// catppuccin replaces some palette entries with Catppuccin Mocha.
type catppuccin struct{}

var _ fyne.Theme = catppuccin{}

func (catppuccin) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	mocha := map[fyne.ThemeColorName]color.Color{
		theme.ColorNameBackground:  color.NRGBA{R: 0x1e, G: 0x1e, B: 0x2e, A: 0xff},
		theme.ColorNameForeground:  color.NRGBA{R: 0xcd, G: 0xd6, B: 0xf4, A: 0xff},
		theme.ColorNamePrimary:     color.NRGBA{R: 0x89, G: 0xb4, B: 0xfa, A: 0xff},
		theme.ColorNameSuccess:     color.NRGBA{R: 0xa6, G: 0xe3, B: 0xa1, A: 0xff},
		theme.ColorNameWarning:     color.NRGBA{R: 0xf9, G: 0xe2, B: 0xaf, A: 0xff},
		theme.ColorNameError:       color.NRGBA{R: 0xf3, G: 0x8b, B: 0xa8, A: 0xff},
		theme.ColorNameDisabled:    color.NRGBA{R: 0x6c, G: 0x70, B: 0x86, A: 0xff},
		theme.ColorNamePlaceHolder: color.NRGBA{R: 0x6c, G: 0x70, B: 0x86, A: 0xff},
		theme.ColorNameScrollBar:   color.NRGBA{R: 0x58, G: 0x5b, B: 0x70, A: 0xff},
		theme.ColorNameButton:      color.NRGBA{R: 0x31, G: 0x32, B: 0x44, A: 0xff},
		theme.ColorNameHover:       color.NRGBA{R: 0x45, G: 0x47, B: 0x5a, A: 0xff},
	}
	if c, ok := mocha[n]; ok {
		return c
	}
	return theme.DefaultTheme().Color(n, v)
}

func (catppuccin) Font(s fyne.TextStyle) fyne.Resource { return theme.DefaultTheme().Font(s) }
func (catppuccin) Icon(n fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(n)
}
func (catppuccin) Size(n fyne.ThemeSizeName) float32 { return theme.DefaultTheme().Size(n) }

func runGUI(ctx context.Context) error {
	a := app.NewWithID("dev.vashuus.passguard")
	a.Settings().SetTheme(catppuccin{})
	w := a.NewWindow("PassGuard")
	w.Resize(fyne.NewSize(560, 460))

	entry := widget.NewPasswordEntry()
	entry.SetPlaceHolder("Escribe una contraseña para auditar")

	gauge := canvas.NewRectangle(color.NRGBA{R: 0x89, G: 0xb4, B: 0xfa, A: 0xcc})
	gauge.SetMinSize(fyne.NewSize(0, 14))

	forceLabel := widget.NewLabel("")
	detailLabel := widget.NewLabel("")
	detailLabel.Wrapping = fyne.TextWrapWord
	leakLabel := widget.NewLabel("")

	update := func() {
		res := strength.Estimate(entry.Text)
		final := 0.3 + 0.7*float32(res.Score)/4
		gauge.FillColor = gaugeColor(res.Score)
		gauge.Resize(fyne.NewSize(500*final, 14))
		forceLabel.SetText(fmt.Sprintf("Fuerza: %s  ·  Entropía: %.1f bits  ·  Tiempo de crack: %s",
			label(res.Score), res.Entropy, res.CrackTime))
		details := ""
		for _, p := range res.Patterns {
			details += fmt.Sprintf("Patrón %q de tipo %s (%.1f bits)\n", p.Token, p.Type, p.Entropy)
		}
		for _, s := range res.Suggestions {
			details += "» " + s + "\n"
		}
		detailLabel.SetText(details)
	}
	entry.OnChanged = func(_ string) { update() }
	update()

	length := widget.NewSlider(12, 64)
	length.SetValue(20)
	lengthLabel := widget.NewLabel("Longitud: 20")
	length.OnChanged = func(v float64) { lengthLabel.SetText(fmt.Sprintf("Longitud: %d", int(v))) }

	withUpper := widget.NewCheck("Mayúsculas", nil)
	withUpper.SetChecked(true)
	withDigits := widget.NewCheck("Dígitos", nil)
	withDigits.SetChecked(true)
	withSymbols := widget.NewCheck("Símbolos", nil)
	withSymbols.SetChecked(true)
	noSimilar := widget.NewCheck("Evitar 1 l I O 0", nil)
	noSimilar.SetChecked(true)

	genButton := widget.NewButton("Generar", func() {
		o := generator.Options{
			Length:     int(length.Value),
			Upper:      withUpper.Checked,
			Digits:     withDigits.Checked,
			Symbols:    withSymbols.Checked,
			NoSimilar:  noSimilar.Checked,
			MinScore:   strength.ScoreSafelyUnguessable,
			MinEntropy: 80,
		}
		pw, err := generator.Generate(o)
		if err != nil {
			leakLabel.SetText("error: " + err.Error())
			return
		}
		entry.SetText(pw)
		w.Clipboard().SetContent(pw)
		leakLabel.SetText("Generada y copiada al portapapeles ✓")
	})
	passButton := widget.NewButton("Frase-pase", func() {
		pw, err := generator.GeneratePassphrase(4)
		if err != nil {
			leakLabel.SetText("error: " + err.Error())
			return
		}
		entry.SetText(pw)
		w.Clipboard().SetContent(pw)
		leakLabel.SetText("Frase-pase copiada al portapapeles ✓")
	})

	leakButton := widget.NewButton("Comprobar filtraciones (HIBP)", func() {
		if entry.Text == "" {
			return
		}
		leakLabel.SetText("Consultando…")
		go func() {
			rep, err := breach.New().Check(entry.Text)
			a.SendNotification(&fyne.Notification{
				Title:   "PassGuard",
				Content: leakMessage(rep, err),
			})
			leakLabel.SetText(leakMessage(rep, err))
		}()
	})

	genRow := container.NewHBox(genButton, passButton, leakButton, lengthLabel)
	optRow := container.NewHBox(withUpper, withDigits, withSymbols, noSimilar, length)

	content := container.NewVBox(
		widget.NewLabel("🔐  PassGuard — Auditor y generador de contraseñas"),
		entry,
		gauge,
		forceLabel,
		detailLabel,
		genRow,
		optRow,
		leakLabel,
	)
	w.SetContent(container.NewPadded(content))
	w.Show()

	<-ctx.Done()
	go func() {
		a.Quit()
	}()
	a.Run()
	return nil
}

func gaugeColor(score int) color.NRGBA {
	switch score {
	case strength.ScoreTooGuessable, strength.ScoreVeryGuessable:
		return color.NRGBA{R: 0xf3, G: 0x8b, B: 0xa8, A: 0xcc}
	case strength.ScoreSomewhatGuessable:
		return color.NRGBA{R: 0xf9, G: 0xe2, B: 0xaf, A: 0xcc}
	case strength.ScoreSafelyUnguessable:
		return color.NRGBA{R: 0x94, G: 0xe2, B: 0xd5, A: 0xcc}
	default:
		return color.NRGBA{R: 0xa6, G: 0xe3, B: 0xa1, A: 0xcc}
	}
}

func leakMessage(rep breach.CheckReport, err error) string {
	if err != nil {
		return "error consultando HIBP: " + err.Error()
	}
	if rep.Found {
		return fmt.Sprintf("¡Aparece en %d filtraciones! No la uses.", rep.Count)
	}
	return "No aparece en filtraciones conocidas de HIBP. ✓"
}
