package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ynotnauk/cloak/internal/keys"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

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

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: cloak <command> [options]")
	fmt.Println("\nCommands:")
	fmt.Println("  keygen [-f|--force]    Generate a new X25519 identity keypair")
}
