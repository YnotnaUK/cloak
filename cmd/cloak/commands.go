package main

import "fmt"

func handleVersion() {
	fmt.Printf("cloak %s (commit: %s, built: %s)\n", version, commit, date)
}

func printUsage() {
	fmt.Println("Usage: cloak [command]")
	fmt.Println("Available commands:")
	fmt.Println("  version - Show the version information")
}
