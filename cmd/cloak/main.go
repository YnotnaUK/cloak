package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ynotnauk/cloak/internal/config"
	"github.com/ynotnauk/cloak/internal/engine"
	"github.com/ynotnauk/cloak/internal/keys"
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

	engine.SetKeyLoader(keys.ReadPrivateKey)

	switch os.Args[1] {
	case "keygen":
		keygenCmd := flag.NewFlagSet("keygen", flag.ExitOnError)
		force := keygenCmd.Bool("force", false, "Overwrite existing key file")
		keygenCmd.BoolVar(force, "f", false, "Overwrite existing key file (shorthand)")
		keygenCmd.Parse(os.Args[2:])

		pubKey, path, err := keys.Generate(*force)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Key generated successfully!\n")
		fmt.Printf("Public Key: %s\n", pubKey)
		fmt.Printf("Saved to:   %s\n", path)

	case "init":
		initCmd := flag.NewFlagSet("init", flag.ExitOnError)
		force := initCmd.Bool("force", false, "Overwrite existing config")
		initCmd.BoolVar(force, "f", false, "Overwrite existing config (shorthand)")

		var recipients stringSlice
		initCmd.Var(&recipients, "r", "Recipient public key (can be repeated)")
		initCmd.Var(&recipients, "recipient", "Recipient public key (can be repeated)")
		initCmd.Parse(os.Args[2:])

		// If no recipients specified, default to local machine key
		if len(recipients) == 0 {
			pubKey, err := keys.ReadPublicKey()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			recipients = append(recipients, pubKey)
		}

		if err := config.Init(recipients, *force); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Initialized %s with %d recipient(s):\n", config.ConfigFileName, len(recipients))
		for _, r := range recipients {
			fmt.Printf("  - %s\n", r)
		}

	case "recipient":
		if len(os.Args) < 3 {
			fmt.Println("Usage: cloak recipient <list>")
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
				fmt.Printf("  %d. %s\n", i+1, r)
			}
		default:
			fmt.Println("Usage: cloak recipient <list>")
			os.Exit(1)
		}

	case "encrypt":
		if err := engine.Process(false); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "decrypt":
		if err := engine.Process(true); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: cloak <command> [options]")
	fmt.Println("\nCommands:")
	fmt.Println("  keygen    [-f|--force]                  Generate a new X25519 identity keypair")
	fmt.Println("  init      [-f] [-r <key> ...]           Create a .cloak.yaml config file")
	fmt.Println("  recipient list                          List all project recipients")
	fmt.Println("  encrypt                                 Encrypt all matching project files in-place")
	fmt.Println("  decrypt                                 Decrypt all matching project files in-place")
}
