package helper

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestRegisterResponse(t *testing.T) {
	input := RegisterInput{
		Origin: "http://localhost",
		CreationOptions: CreationOptions{
			Challenge: "challenge-123",
			RP: RP{ID: "localhost", Name: "Lineage invite-network"},
			User: User{ID: "user-1", Name: "alice", DisplayName: "alice"},
			PubKeyCredParams: []PubKeyCredParam{{Type: "public-key", Alg: -7}},
		},
	}
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
	if output.Credential.PrivateKeyPEM == "" {
		t.Fatal("expected private key material")
	}
	if output.Credential.RPID != "localhost" {
		t.Fatalf("expected rp id localhost, got %q", output.Credential.RPID)
	}

	decodedClientData, err := base64.RawURLEncoding.DecodeString(output.AttestationResponse.Response.ClientDataJSON)
	if err != nil {
		t.Fatalf("failed to decode clientDataJSON: %v", err)
	}
	var clientData map[string]any
	if err := json.Unmarshal(decodedClientData, &clientData); err != nil {
		t.Fatalf("failed to unmarshal clientDataJSON: %v", err)
	}
	if clientData["type"] != "webauthn.create" {
		t.Fatalf("expected webauthn.create, got %#v", clientData["type"])
	}
}

func TestLoginResponse(t *testing.T) {
	registered, err := RegisterResponse(RegisterInput{
		Origin: "http://localhost",
		CreationOptions: CreationOptions{
			Challenge: "challenge-register",
			RP: RP{ID: "localhost", Name: "Lineage invite-network"},
			User: User{ID: "user-1", Name: "alice", DisplayName: "alice"},
			PubKeyCredParams: []PubKeyCredParam{{Type: "public-key", Alg: -7}},
		},
	})
	if err != nil {
		t.Fatalf("register setup failed: %v", err)
	}

	login, err := LoginResponse(LoginInput{
		Origin: "http://localhost",
		RequestOptions: RequestOptions{
			Challenge: "challenge-login",
			RPID: "localhost",
		},
		Credential: registered.Credential,
	})
	if err != nil {
		t.Fatalf("LoginResponse returned error: %v", err)
	}
	if login.AssertionResponse.ID == "" {
		t.Fatal("expected non-empty assertion response id")
	}
	if login.Credential.SignCount != registered.Credential.SignCount+1 {
		t.Fatalf("expected signCount %d, got %d", registered.Credential.SignCount+1, login.Credential.SignCount)
	}
	decodedClientData, err := base64.RawURLEncoding.DecodeString(login.AssertionResponse.Response.ClientDataJSON)
	if err != nil {
		t.Fatalf("failed to decode clientDataJSON: %v", err)
	}
	var clientData map[string]any
	if err := json.Unmarshal(decodedClientData, &clientData); err != nil {
		t.Fatalf("failed to unmarshal clientDataJSON: %v", err)
	}
	if clientData["type"] != "webauthn.get" {
		t.Fatalf("expected webauthn.get, got %#v", clientData["type"])
	}
	decodedAuthData, err := base64.RawURLEncoding.DecodeString(login.AssertionResponse.Response.AuthenticatorData)
	if err != nil {
		t.Fatalf("failed to decode authenticatorData: %v", err)
	}
	var authData map[string]any
	if err := json.Unmarshal(decodedAuthData, &authData); err != nil {
		t.Fatalf("failed to unmarshal authenticatorData: %v", err)
	}
	if authData["rpId"] != "localhost" {
		t.Fatalf("expected rpId localhost, got %#v", authData["rpId"])
	}
}
