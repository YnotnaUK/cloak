package main

import (
	"flag"
	"fmt"

	"github.com/YnotnaUK/cloak/internal/crypto"
	"github.com/YnotnaUK/cloak/internal/identity"
)

func handleKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	force := fs.Bool("force", false, "Overwrite existing keys if they exist")
	_ = fs.Parse(args)

	// 1. Generate the raw keys
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}

	// 2. Save them safely to disk
	privPath, pubPath, err := identity.SaveKeyPair(kp, *force)
	if err != nil {
		return err
	}

	// 3. Print clean user output
	fmt.Printf("✔ Generated new keypair:\n")
	fmt.Printf("  Private Identity (-i): %s  (permissions: 0600)\n", privPath)
	fmt.Printf("  Public Recipient (-r): %s  (permissions: 0644)\n\n", pubPath)

	fmt.Printf("Your Public Recipient Key:\n")
	fmt.Printf("  %s\n\n", kp.Public)

	fmt.Printf("To initialize a project with this key, run:\n")
	fmt.Printf("  cloak init -r %s\n", kp.Public)

	return nil
}
