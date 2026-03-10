package helper

import "testing"

func TestRegisterResponse(t *testing.T) {
	input := RegisterInput{}
	output, err := RegisterResponse(input)
	if err != nil {
		t.Fatalf("RegisterResponse returned error: %v", err)
	}
	if output.AttestationResponse.ID == "" {
		t.Fatal("expected non-empty attestation response id")
	}
	if output.Credential.ID == "" {
		t.Fatal("expected non-empty credential id")
	}
}
