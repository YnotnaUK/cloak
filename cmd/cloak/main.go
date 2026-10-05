package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/ynotnauk/cloak/internal/config"
	"github.com/ynotnauk/cloak/internal/engine"
	"github.com/ynotnauk/cloak/internal/keys"
	"github.com/ynotnauk/cloak/internal/updater"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// stringSlice allows repeated flags: -r key1 -r key2
type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSlice) Set(val string) error {
	*s = append(*s, strings.TrimSpace(val))
	return nil
}

func main() {

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	if cmd != "version" && cmd != "update" {
		defer updater.StartCheck(Version)()
	}

	engine.SetKeyLoader(keys.ReadPrivateKey)

	switch cmd {
	case "keygen":
		keygenCmd := flag.NewFlagSet("keygen", flag.ExitOnError)
		var opts keys.Options
		keygenCmd.BoolVar(&opts.Force, "force", false, "Overwrite existing key file")
		keygenCmd.BoolVar(&opts.Force, "f", false, "Overwrite existing key file (shorthand)")
		keygenCmd.StringVar(&opts.Path, "out", "", "Write the key to this file instead of the default location")
		keygenCmd.StringVar(&opts.Path, "output", "", "Alias for --out")
		keygenCmd.StringVar(&opts.Path, "o", "", "Alias for --out")
		keygenCmd.BoolVar(&opts.Stdout, "stdout", false, "Print the key to stdout instead of writing a file")
		keygenCmd.StringVar(&opts.Name, "name", "", "Label stored in the key file header")
		if err := keygenCmd.Parse(os.Args[2:]); err != nil {
			os.Exit(2)
		}

		res, err := keys.Generate(opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if opts.Stdout {
			// Private key goes to stdout only, so it can be piped; messages go to stderr.
			fmt.Print(res.Content)
			fmt.Fprintf(os.Stderr, "Public Key: %s\n", res.PublicKey)
			break
		}
		fmt.Printf("Key generated successfully!\n")
		fmt.Printf("Public Key: %s\n", res.PublicKey)
		fmt.Printf("Saved to:   %s\n", res.Path)
		if opts.Path != "" || opts.Name != "" {
			name := opts.Name
			if name == "" {
				name = "<name>"
			}
			fmt.Printf("\nTo grant this key access to a project, run:\n  cloak recipient add %s --name %s\n", res.PublicKey, name)
		}

	case "init":
		initCmd := flag.NewFlagSet("init", flag.ExitOnError)
		force := initCmd.Bool("force", false, "Overwrite existing config")
		initCmd.BoolVar(force, "f", false, "Overwrite existing config (shorthand)")

		var rawRecipients stringSlice
		initCmd.Var(&rawRecipients, "r", "Recipient as name=public_key (can be repeated)")
		initCmd.Var(&rawRecipients, "recipient", "Recipient as name=public_key (can be repeated)")
		if err := initCmd.Parse(os.Args[2:]); err != nil {
			os.Exit(2)
		}

		var recipients []config.Recipient
		for _, raw := range rawRecipients {
			name, key, ok := strings.Cut(raw, "=")
			if !ok {
				fmt.Fprintf(os.Stderr, "Error: recipient %q must be in the form name=public_key\n", raw)
				os.Exit(1)
			}
			recipients = append(recipients, config.Recipient{Name: strings.TrimSpace(name), Key: strings.TrimSpace(key)})
		}

		// If no recipients specified, default to local machine key
		if len(recipients) == 0 {
			pubKey, err := keys.ReadPublicKey()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			name := "default"
			if u, err := user.Current(); err == nil && u.Username != "" {
				name = u.Username
			}
			recipients = append(recipients, config.Recipient{Name: name, Key: pubKey})
		}

		if err := config.Init(recipients, *force); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Initialized %s with %d recipient(s):\n", config.ConfigFileName, len(recipients))
		for _, r := range recipients {
			fmt.Printf("  - %s (%s)\n", r.Name, r.Key)
		}

	case "recipient":
		if len(os.Args) < 3 {
			fmt.Println(recipientUsage)
			os.Exit(1)
		}

		switch os.Args[2] {
		case "list":
			cfg, err := config.Load()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Configured recipients in %s:\n", config.ConfigFileName)
			for i, r := range cfg.Recipients {
				fmt.Printf("  %d. %-20s %-11s %s\n", i+1, r.Name, r.Kind, r.Key)
			}

		case "add":
			addCmd := flag.NewFlagSet("recipient add", flag.ExitOnError)
			name := addCmd.String("name", "", "Unique recipient name (required)")
			kind := addCmd.String("kind", config.KindUser, "Recipient kind: user, ci or breakglass")
			// Allow the key before or after the flags.
			args := os.Args[3:]
			var keyToAdd string
			if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
				keyToAdd, args = args[0], args[1:]
			}
			if err := addCmd.Parse(args); err != nil {
				os.Exit(2)
			}
			if keyToAdd == "" && addCmd.NArg() == 1 {
				keyToAdd = addCmd.Arg(0)
			}
			if keyToAdd == "" || *name == "" {
				fmt.Println("Usage: cloak recipient add <public_key_hex> --name <name> [--kind user|ci|breakglass]")
				os.Exit(1)
			}

			cfg, err := config.Load()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			if err := cfg.AddRecipient(*name, keyToAdd, *kind); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Added recipient: %s (%s)\n", *name, keyToAdd)
			fmt.Println("Rotating DEK and re-keying project files...")
			if err := engine.Rekey(); err != nil {
				fmt.Fprintf(os.Stderr, "Error re-keying: %v\n", err)
				os.Exit(1)
			}

		case "remove":
			if len(os.Args) < 4 {
				fmt.Println("Usage: cloak recipient remove <name|public_key_hex>")
				os.Exit(1)
			}

			cfg, err := config.Load()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			removed, err := cfg.RemoveRecipient(os.Args[3])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Removed recipient: %s (%s)\n", removed.Name, removed.Key)
			fmt.Println("Rotating DEK and re-keying project files...")
			if err := engine.Rekey(); err != nil {
				fmt.Fprintf(os.Stderr, "Error re-keying: %v\n", err)
				os.Exit(1)
			}

		default:
			fmt.Println(recipientUsage)
			os.Exit(1)
		}

	case "rekey":
		if err := engine.Rekey(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "encrypt":
		encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
		files, err := parseInterspersed(encryptCmd, os.Args[2:])
		if err != nil {
			os.Exit(2)
		}
		if err := engine.Process(false, files); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "decrypt":
		decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
		var inPlace, noNewline bool
		var extract string
		decryptCmd.BoolVar(&inPlace, "in-place", false, "Write plaintext back to the file(s) on disk")
		decryptCmd.BoolVar(&inPlace, "i", false, "Shorthand for --in-place")
		decryptCmd.StringVar(&extract, "extract", "", "Print a single value by dot-separated path")
		decryptCmd.StringVar(&extract, "e", "", "Shorthand for --extract")
		decryptCmd.BoolVar(&noNewline, "no-newline", false, "Omit the trailing newline after an extracted value")
		decryptCmd.BoolVar(&noNewline, "n", false, "Shorthand for --no-newline")
		files, err := parseInterspersed(decryptCmd, os.Args[2:])
		if err != nil {
			os.Exit(2)
		}

		if err := runDecrypt(files, inPlace, extract, noNewline); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "edit":
		editCmd := flag.NewFlagSet("edit", flag.ExitOnError)
		files, err := parseInterspersed(editCmd, os.Args[2:])
		if err != nil {
			os.Exit(2)
		}
		if len(files) != 1 {
			fmt.Println("Usage: cloak edit <file>")
			os.Exit(1)
		}

		res, err := engine.Edit(files[0], engine.EditOptions{Retry: promptRetry})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			if res.KeptPath != "" {
				fmt.Fprintf(os.Stderr, "Your edits (plaintext) were left at %s; delete it when done.\n", res.KeptPath)
			}
			os.Exit(1)
		}
		if res.Changed {
			fmt.Fprintf(os.Stderr, "Updated: %s\n", files[0])
		} else {
			fmt.Fprintln(os.Stderr, "No changes made.")
		}

	case "version":
		fmt.Printf("cloak %s (commit: %s, built at: %s)\n", Version, Commit, Date)
		if latest, hasUpdate := updater.CheckLatest(Version); hasUpdate {
			fmt.Printf("\n[notice] A new version of cloak is available: %s (current: %s)\n", latest, Version)
			fmt.Println("[notice] To update, run: cloak update")
		}

	case "update":
		if err := updater.Upgrade(Version); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	default:
		printUsage()
		os.Exit(1)
	}
}

const recipientUsage = "Usage: cloak recipient <list|add|remove> [args]"

// parseInterspersed parses flags that may appear before or after positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

func runDecrypt(files []string, inPlace bool, extract string, noNewline bool) error {
	if inPlace && extract != "" {
		return errors.New("cannot combine --in-place and --extract")
	}
	if noNewline && extract == "" {
		return errors.New("--no-newline requires --extract")
	}

	if inPlace {
		return engine.Process(true, files)
	}

	if len(files) != 1 {
		return errors.New("specify exactly one file to print (or use --in-place to decrypt files on disk)")
	}

	if extract != "" {
		val, err := engine.ExtractValue(files[0], extract)
		if err != nil {
			return err
		}
		if !noNewline {
			val = append(val, '\n')
		}
		_, err = os.Stdout.Write(val)
		return err
	}

	out, err := engine.DecryptFile(files[0])
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}

func promptRetry(reason error) bool {
	fmt.Fprintf(os.Stderr, "Error: %v\nReopen the editor? [Y/n] ", reason)
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "" || answer == "y" || answer == "yes"
}

func printUsage() {
	fmt.Println("Usage: cloak <command> [options]")
	fmt.Println("\nCommands:")
	fmt.Println("  keygen    [-f] [-o|--out|--output <file>] [--stdout] [--name <label>]")
	fmt.Println("                                          Generate a new X25519 identity keypair")
	fmt.Println("  init      [-f] [-r <name>=<key> ...]    Create a .cloak.yaml config file")
	fmt.Println("  recipient list                          List all project recipients")
	fmt.Println("  recipient add <key> --name <name> [--kind user|ci|breakglass]")
	fmt.Println("                                          Add recipient & rekey files")
	fmt.Println("  recipient remove <name|key>             Remove recipient & rekey files")
	fmt.Println("  edit      <file>                        Edit a secret file in $EDITOR, re-encrypting on save")
	fmt.Println("  rekey                                   Rotate DEK and re-encrypt files")
	fmt.Println("  encrypt   [file ...]                    Encrypt files in-place (all matching files if none given)")
	fmt.Println("  decrypt   <file>                        Print the decrypted file to stdout")
	fmt.Println("  decrypt   <file> -e <path> [-n]         Print a single decrypted value")
	fmt.Println("  decrypt   -i [file ...]                 Decrypt files in-place (all matching files if none given)")
	fmt.Println("  version                                 Show cloak version information")
	fmt.Println("  update                                  Self-update to the latest release")
}
