package helper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
)

type attestationObject struct {
	Fmt      string         `json:"fmt"`
	AuthData authDataObject `json:"authData"`
}

type authDataObject struct {
	RPID         string `json:"rpId"`
	RPIDHash     string `json:"rpIdHash"`
	CredentialID string `json:"credentialId"`
	PublicKey    string `json:"publicKey"`
	PublicKeyPEM string `json:"publicKeyPem"`
	Algorithm    int    `json:"algorithm"`
	SignCount    uint32 `json:"signCount"`
	Transports   []string `json:"transports"`
}

func RegisterResponse(input RegisterInput) (RegisterOutput, error) {
	if input.CreationOptions.RP.ID == "" {
		return RegisterOutput{}, errors.New("missing rp id")
	}
	if input.CreationOptions.User.ID == "" {
		return RegisterOutput{}, errors.New("missing user id")
	}
	alg := -7
	if len(input.CreationOptions.PubKeyCredParams) > 0 {
		alg = input.CreationOptions.PubKeyCredParams[0].Alg
	}
	if alg != -7 {
		return RegisterOutput{}, errors.New("unsupported algorithm")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return RegisterOutput{}, err
	}
	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return RegisterOutput{}, err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER})
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return RegisterOutput{}, err
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})

	credentialIDBytes := make([]byte, 32)
	if _, err := rand.Read(credentialIDBytes); err != nil {
		return RegisterOutput{}, err
	}
	credentialID := base64.RawURLEncoding.EncodeToString(credentialIDBytes)

	clientDataJSONBytes, err := json.Marshal(map[string]any{
		"type": "webauthn.create",
		"challenge": input.CreationOptions.Challenge,
		"origin": input.Origin,
		"crossOrigin": false,
	})
	if err != nil {
		return RegisterOutput{}, err
	}

	rpHashX, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	attestationObjectBytes, err := json.Marshal(attestationObject{
		Fmt: "none",
		AuthData: authDataObject{
			RPID:         input.CreationOptions.RP.ID,
			RPIDHash:     rpHashX.Text(16),
			CredentialID: credentialID,
			PublicKey:    base64.RawURLEncoding.EncodeToString(publicDER),
			PublicKeyPEM: string(publicPEM),
			Algorithm:    alg,
			SignCount:    0,
			Transports:   []string{"internal"},
		},
	})
	if err != nil {
		return RegisterOutput{}, err
	}

	credential := Credential{
		ID:            credentialID,
		UserID:        input.CreationOptions.User.ID,
		RPID:          input.CreationOptions.RP.ID,
		Algorithm:     alg,
		PublicKeyPEM:  string(publicPEM),
		PrivateKeyPEM: string(privatePEM),
		SignCount:     0,
	}

	return RegisterOutput{
		AttestationResponse: AttestationResponse{
			ID:    credentialID,
			RawID: credentialID,
			Type:  "public-key",
			Response: AuthenticatorAttestationResponse{
				ClientDataJSON:    base64.RawURLEncoding.EncodeToString(clientDataJSONBytes),
				AttestationObject: base64.RawURLEncoding.EncodeToString(attestationObjectBytes),
			},
		},
		Credential: credential,
	}, nil
}
