package main

import (
	"fmt"
	"os"

	"github.com/Vashuus/passguard/internal/generator"
	"github.com/Vashuus/passguard/internal/strength"
	"github.com/spf13/cobra"
)

// rune display helper for the strength gauge
func bar(score int) string {
	const n = 8
	out := make([]rune, n)
	for i := range out {
		if i < score+1 {
			out[i] = '█'
		} else {
			out[i] = '░'
		}
	}
	return string(out)
}

func label(score int) string {
	switch score {
	case strength.ScoreTooGuessable:
		return "INSERVIBLE"
	case strength.ScoreVeryGuessable:
		return "MUY DÉBIL"
	case strength.ScoreSomewhatGuessable:
		return "DÉBIL"
	case strength.ScoreSafelyUnguessable:
		return "BUENA"
	default:
		return "EXCELENTE"
	}
}

func main() {
	root := &cobra.Command{
		Use:     "passguard",
		Short:   "Generador y auditor de contraseñas difícilmente automatizables",
		Long:    "PassGuard: genera y audita contraseñas con entropía alta y patrones\nresistidos, en terminal (TUI), ventana (GUI) o línea de comandos.",
		Version: "0.1.0",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gui, _ := cmd.Flags().GetBool("gui")
			if gui {
				return runGUI(cmd.Context())
			}
			return runTUI(cmd.Context())
		},
	}
	root.Flags().Bool("gui", false, "abrir la interfaz gráfica (Fyne)")

	check := &cobra.Command{
		Use:   "check \"contraseña\"",
		Short: "Evaluar la resistencia de una contraseña",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			res := strength.Estimate(args[0])
			fmt.Printf("Entropía       %7.1f bits\n", res.Entropy)
			fmt.Printf("Intentos       %7.0e\n", res.Guesses)
			fmt.Printf("Tiempo crack   %s (offline rápido)\n", res.CrackTime)
			fmt.Printf("Fuerza         %s [%s]\n", label(res.Score), bar(res.Score))
			if res.Warning != "" {
				fmt.Printf("Nota: %s\n", res.Warning)
			}
			if len(res.Patterns) > 0 {
				fmt.Println("Patrones detectados:")
				for _, p := range res.Patterns {
					fmt.Printf("  - %-10s %q (%.1f bits)\n", p.Type, p.Token, p.Entropy)
				}
			}
			for _, s := range res.Suggestions {
				fmt.Println("  Sugerencia:", s)
			}
			return nil
		},
	}

	var (
		length  int
		upper   bool
		digs    bool
		symbols bool
		similar bool
	)
	gen := &cobra.Command{
		Use:   "gen",
		Short: "Generar contraseña segura (CSPRNG + revisión)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			o := generator.Options{
				Length:     length,
				Upper:      upper,
				Digits:     digs,
				Symbols:    symbols,
				NoSimilar:  !similar,
				MinScore:   strength.ScoreSafelyUnguessable,
				MinEntropy: 80,
			}
			pw, err := generator.Generate(o)
			if err != nil {
				return err
			}
			res := strength.Estimate(pw)
			fmt.Println("Contraseña generada:")
			fmt.Printf("  %s\n", pw)
			fmt.Printf("  Entropía: %.1f bits · Fuerza: %s\n", res.Entropy, label(res.Score))
			return nil
		},
	}
	gen.Flags().IntVarP(&length, "length", "l", 20, "longitud (mínimo 12)")
	gen.Flags().BoolVar(&upper, "upper", true, "incluir mayúsculas")
	gen.Flags().BoolVar(&digs, "digits", true, "incluir dígitos")
	gen.Flags().BoolVar(&symbols, "symbols", true, "incluir símbolos")
	gen.Flags().BoolVar(&similar, "similar", false, "permitir caracteres similares (1 l I O 0)")

	passphrase := &cobra.Command{
		Use:   "passphrase",
		Short: "Generar frase-pase memorable (diceware)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			n, _ := cmd.Flags().GetInt("words")
			pw, err := generator.GeneratePassphrase(n)
			if err != nil {
				return err
			}
			res := strength.Estimate(pw)
			fmt.Println("Frase-pase:")
			fmt.Printf("  %s\n", pw)
			fmt.Printf("  Entropía: %.1f bits · Fuerza: %s\n", res.Entropy, label(res.Score))
			return nil
		},
	}
	passphrase.Flags().IntP("words", "w", 4, "número de palabras")

	leak := &cobra.Command{
		Use:   "leak \"contraseña\"",
		Short: "Comprobar si apareció en una filtración (HIBP k-anónimo)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			rep, err := breachClient().Check(args[0])
			if err != nil {
				return err
			}
			if rep.Found {
				fmt.Printf("¡ENCONTRADA! %d veces en bases de datos de filtraciones.\n", rep.Count)
				fmt.Println("Nunca la uses. Genera una nueva con `passguard gen`.")
			} else {
				fmt.Println("No aparece en las filtraciones conocidas de HIBP. Bien.")
			}
			return nil
		},
	}

	root.AddCommand(check, gen, passphrase, leak)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
