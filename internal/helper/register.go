package helper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
)

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
	credentialID := base64url(credentialIDBytes)

	clientDataJSONBytes, err := json.Marshal(map[string]any{
		"type":        "webauthn.create",
		"challenge":   input.CreationOptions.Challenge,
		"origin":      input.Origin,
		"crossOrigin": false,
	})
	if err != nil {
		return RegisterOutput{}, err
	}

	attestationObjectBytes, authenticatorDataBytes, err := makeAttestationObject(
		input.CreationOptions.RP.ID,
		credentialIDBytes,
		&privateKey.PublicKey,
	)
	if err != nil {
		return RegisterOutput{}, err
	}

	credential := Credential{
		ID:            credentialID,
		UserID:        input.CreationOptions.User.ID,
		RPID:          input.CreationOptions.RP.ID,
		Algorithm:     alg,
		PublicKey:     base64url(publicDER),
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
				ClientDataJSON:    base64url(clientDataJSONBytes),
				AttestationObject: base64url(attestationObjectBytes),
				AuthenticatorData: base64url(authenticatorDataBytes),
				PublicKey:         base64url(publicDER),
				PublicKeyAlgorithm: alg,
				Transports:        []string{"internal"},
			},
		},
		Credential: credential,
	}, nil
}
