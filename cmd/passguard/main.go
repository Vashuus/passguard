package main

import (
	"fmt"
	"os"

	"github.com/Vashuus/passguard/internal/clipboard"
	"github.com/Vashuus/passguard/internal/console"
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
		return "INSECURE"
	case strength.ScoreVeryGuessable:
		return "VERY WEAK"
	case strength.ScoreSomewhatGuessable:
		return "WEAK"
	case strength.ScoreSafelyUnguessable:
		return "GOOD"
	default:
		return "EXCELLENT"
	}
}

func printGenerated(pw string, res strength.Result) {
	fmt.Println("Generated password:")
	fmt.Printf("  %s\n", pw)
	fmt.Printf("  Entropy: %.1f bits · Strength: %s\n", res.Entropy, label(res.Score))
}

func copyOrHint(pw string) error {
	if err := clipboard.Copy(pw); err != nil {
		fmt.Printf("  Copy to clipboard failed: %v (you can still copy it manually)\n", err)
		return nil
	}
	fmt.Println("  Copied to the clipboard.")
	return nil
}

func main() {
	root := &cobra.Command{
		Use:     "passguard",
		Short:   "AI-resistant password auditor and generator",
		Long:    "PassGuard: generates and audits passwords with high entropy and\nresisted patterns, in a terminal (TUI), a window (GUI) or the CLI.",
		Version: "0.3.0",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			gui, _ := cmd.Flags().GetBool("gui")
			if gui || console.AutoGUI() {
				return runGUI(cmd.Context())
			}
			return runTUI(cmd.Context())
		},
	}
	root.Flags().Bool("gui", false, "open the graphical interface (Fyne)")

	check := &cobra.Command{
		Use:   "check \"password\"",
		Short: "Evaluate the resistance of a password",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			res := strength.Estimate(args[0])
			fmt.Printf("Entropy       %7.1f bits\n", res.Entropy)
			fmt.Printf("Guesses       %7.0e\n", res.Guesses)
			fmt.Printf("Crack time    %s (fast offline)\n", res.CrackTime)
			fmt.Printf("Strength      %s [%s]\n", label(res.Score), bar(res.Score))
			if res.Warning != "" {
				fmt.Printf("Note: %s\n", res.Warning)
			}
			if len(res.Patterns) > 0 {
				fmt.Println("Detected patterns:")
				for _, p := range res.Patterns {
					fmt.Printf("  - %-10s %q (%.1f bits)\n", p.Type, p.Token, p.Entropy)
				}
			}
			for _, s := range res.Suggestions {
				fmt.Println("  Suggestion:", s)
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
		copyOut bool
	)
	gen := &cobra.Command{
		Use:   "gen",
		Short: "Generate a strong password (CSPRNG + review)",
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
			printGenerated(pw, res)
			if copyOut {
				return copyOrHint(pw)
			}
			return nil
		},
	}
	gen.Flags().IntVarP(&length, "length", "l", 20, "length (minimum 12)")
	gen.Flags().BoolVar(&upper, "upper", true, "include uppercase")
	gen.Flags().BoolVar(&digs, "digits", true, "include digits")
	gen.Flags().BoolVar(&symbols, "symbols", true, "include symbols")
	gen.Flags().BoolVar(&similar, "similar", false, "allow similar characters (1 l I O 0)")
	gen.Flags().BoolVarP(&copyOut, "copy", "c", false, "copy the result to the clipboard")

	passphrase := &cobra.Command{
		Use:   "passphrase",
		Short: "Generate a memorable passphrase (diceware)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			n, _ := cmd.Flags().GetInt("words")
			pw, err := generator.GeneratePassphrase(n)
			if err != nil {
				return err
			}
			res := strength.Estimate(pw)
			printGenerated(pw, res)
			if copyOut {
				return copyOrHint(pw)
			}
			return nil
		},
	}
	passphrase.Flags().IntP("words", "w", 4, "number of words")
	passphrase.Flags().BoolVarP(&copyOut, "copy", "c", false, "copy the result to the clipboard")

	leak := &cobra.Command{
		Use:   "leak \"password\"",
		Short: "Check whether it appeared in a breach (HIBP k-anonymous)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			rep, err := breachClient().Check(args[0])
			if err != nil {
				return err
			}
			if rep.Found {
				fmt.Printf("FOUND! %d times in breach databases.\n", rep.Count)
				fmt.Println("Never use it. Generate a new one with `passguard gen`.")
			} else {
				fmt.Println("Not found in known HIBP breaches. Good.")
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
