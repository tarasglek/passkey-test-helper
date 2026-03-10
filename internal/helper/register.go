package helper

func RegisterResponse(_ RegisterInput) (RegisterOutput, error) {
	return RegisterOutput{
		AttestationResponse: AttestationResponse{ID: "stub-attestation", Type: "public-key"},
		Credential:          Credential{ID: "stub-credential"},
	}, nil
}
