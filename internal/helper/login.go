package helper

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"encoding/json"
)

type ecdsaSignature struct {
	R, S *big.Int
}

func LoginResponse(input LoginInput) (LoginOutput, error) {
	if input.RequestOptions.RPID == "" {
		return LoginOutput{}, errors.New("missing rp id")
	}
	if input.Credential.PrivateKeyPEM == "" {
		return LoginOutput{}, errors.New("missing private key")
	}
	if input.Credential.RPID != input.RequestOptions.RPID {
		return LoginOutput{}, errors.New("rp id mismatch")
	}

	block, _ := pem.Decode([]byte(input.Credential.PrivateKeyPEM))
	if block == nil {
		return LoginOutput{}, errors.New("failed to decode private key pem")
	}
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return LoginOutput{}, err
	}

	clientDataJSONBytes, err := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   input.RequestOptions.Challenge,
		"origin":      input.Origin,
		"crossOrigin": false,
	})
	if err != nil {
		return LoginOutput{}, err
	}

	updatedCredential := input.Credential
	updatedCredential.SignCount += 1
	authDataBytes := makeAssertionAuthData(input.RequestOptions.RPID, updatedCredential.SignCount, true)

	clientHash := sha256.Sum256(clientDataJSONBytes)
	toSign := append(append([]byte{}, authDataBytes...), clientHash[:]...)
	digest := sha256.Sum256(toSign)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		return LoginOutput{}, err
	}
	signatureDER, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		return LoginOutput{}, err
	}

	return LoginOutput{
		AssertionResponse: AssertionResponse{
			ID:    input.Credential.ID,
			RawID: input.Credential.ID,
			Type:  "public-key",
			Response: AuthenticatorAssertionResponse{
				ClientDataJSON:    base64url(clientDataJSONBytes),
				AuthenticatorData: base64url(authDataBytes),
				Signature:         base64url(signatureDER),
				UserHandle:        base64url([]byte(input.Credential.UserID)),
			},
		},
		Credential: updatedCredential,
	}, nil
}
