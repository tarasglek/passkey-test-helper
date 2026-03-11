package helper

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

func base64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func rpIDHash(rpID string) []byte {
	sum := sha256.Sum256([]byte(rpID))
	return sum[:]
}

func makeAssertionAuthData(rpID string, signCount uint32, userVerified bool) []byte {
	flags := byte(0x01)
	if userVerified {
		flags |= 0x04
	}

	buf := make([]byte, 0, 37)
	buf = append(buf, rpIDHash(rpID)...)
	buf = append(buf, flags)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, signCount)
	buf = append(buf, counter...)
	return buf
}

func coseEC2PublicKey(pub *ecdsa.PublicKey) (map[int]any, error) {
	if pub == nil {
		return nil, errors.New("missing public key")
	}
	x := pub.X.FillBytes(make([]byte, 32))
	y := pub.Y.FillBytes(make([]byte, 32))
	return map[int]any{
		1:  2,
		3:  -7,
		-1: 1,
		-2: x,
		-3: y,
	}, nil
}

func makeAttestationObject(rpID string, credentialID []byte, pub *ecdsa.PublicKey) ([]byte, []byte, error) {
	coseKey, err := coseEC2PublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	coseKeyBytes, err := cbor.Marshal(coseKey)
	if err != nil {
		return nil, nil, err
	}

	flags := byte(0x41 | 0x04)
	aaguid := make([]byte, 16)
	credLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credLen, uint16(len(credentialID)))
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, 0)

	authData := make([]byte, 0, 32+1+4+16+2+len(credentialID)+len(coseKeyBytes))
	authData = append(authData, rpIDHash(rpID)...)
	authData = append(authData, flags)
	authData = append(authData, counter...)
	authData = append(authData, aaguid...)
	authData = append(authData, credLen...)
	authData = append(authData, credentialID...)
	authData = append(authData, coseKeyBytes...)

	attestationObject := map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	}
	attestationObjectBytes, err := cbor.Marshal(attestationObject)
	if err != nil {
		return nil, nil, err
	}

	return attestationObjectBytes, authData, nil
}
