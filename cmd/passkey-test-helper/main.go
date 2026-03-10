package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/taras/passkey-test-helper/internal/helper"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: passkey-test-helper <command>")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "register-response":
		var input helper.RegisterInput
		if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil && err.Error() != "EOF" {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		output, err := helper.RegisterResponse(input)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "login-response":
		var input helper.LoginInput
		if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil && err.Error() != "EOF" {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		output, err := helper.LoginResponse(input)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(2)
	}
}
