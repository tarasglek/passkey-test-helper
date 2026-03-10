package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/taras/passkey-test-helper/internal/helper"
)

func TestRegisterResponseCLI(t *testing.T) {
	input := helper.RegisterInput{
		Origin: "http://localhost",
		CreationOptions: helper.CreationOptions{
			Challenge: "challenge-123",
			RP: helper.RP{ID: "localhost", Name: "Lineage invite-network"},
			User: helper.User{ID: "user-1", Name: "alice", DisplayName: "alice"},
			PubKeyCredParams: []helper.PubKeyCredParam{{Type: "public-key", Alg: -7}},
		},
	}
	stdout, stderr, err := runCLI([]string{"passkey-test-helper", "register-response"}, input)
	if err != nil {
		t.Fatalf("runCLI returned error: %v, stderr=%s", err, stderr)
	}
	var output helper.RegisterOutput
	if err := json.Unmarshal(stdout, &output); err != nil {
		t.Fatalf("failed to unmarshal stdout: %v", err)
	}
	if output.AttestationResponse.ID == "" {
		t.Fatal("expected attestation response id")
	}
}

func TestLoginResponseCLI(t *testing.T) {
	registered, err := helper.RegisterResponse(helper.RegisterInput{
		Origin: "http://localhost",
		CreationOptions: helper.CreationOptions{
			Challenge: "challenge-register",
			RP: helper.RP{ID: "localhost", Name: "Lineage invite-network"},
			User: helper.User{ID: "user-1", Name: "alice", DisplayName: "alice"},
			PubKeyCredParams: []helper.PubKeyCredParam{{Type: "public-key", Alg: -7}},
		},
	})
	if err != nil {
		t.Fatalf("register setup failed: %v", err)
	}

	input := helper.LoginInput{
		Origin: "http://localhost",
		RequestOptions: helper.RequestOptions{Challenge: "challenge-login", RPID: "localhost"},
		Credential: registered.Credential,
	}
	stdout, stderr, err := runCLI([]string{"passkey-test-helper", "login-response"}, input)
	if err != nil {
		t.Fatalf("runCLI returned error: %v, stderr=%s", err, stderr)
	}
	var output helper.LoginOutput
	if err := json.Unmarshal(stdout, &output); err != nil {
		t.Fatalf("failed to unmarshal stdout: %v", err)
	}
	if output.AssertionResponse.ID == "" {
		t.Fatal("expected assertion response id")
	}
}

func runCLI(args []string, input any) ([]byte, []byte, error) {
	stdinData, err := json.Marshal(input)
	if err != nil {
		return nil, nil, err
	}

	oldArgs := os.Args
	oldStdin := os.Stdin
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	defer func() {
		os.Args = oldArgs
		os.Stdin = oldStdin
		os.Stdout = oldStdout
		os.Stderr = oldStderr
	}()

	os.Args = args

	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}

	if _, err := stdinWriter.Write(stdinData); err != nil {
		return nil, nil, err
	}
	stdinWriter.Close()
	os.Stdin = stdinReader
	os.Stdout = stdoutWriter
	os.Stderr = stderrWriter

	var panicValue any
	func() {
		defer func() { panicValue = recover() }()
		main()
	}()

	stdoutWriter.Close()
	stderrWriter.Close()
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	stdout.ReadFrom(stdoutReader)
	stderr.ReadFrom(stderrReader)

	if panicValue != nil {
		return stdout.Bytes(), stderr.Bytes(), panicValue.(error)
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}
