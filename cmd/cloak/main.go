package main

import (
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
		pubKey, path, err := keys.Generate()
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
	fmt.Println("Usage: cloak <command>")
	fmt.Println("\nCommands:")
	fmt.Println("  keygen    Generate a new X25519 identity keypair")
}
