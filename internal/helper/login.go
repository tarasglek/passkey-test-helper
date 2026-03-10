package helper

func LoginResponse(_ LoginInput) (LoginOutput, error) {
	return LoginOutput{
		AssertionResponse: AssertionResponse{ID: "stub-assertion", Type: "public-key"},
		Credential:        Credential{ID: "stub-credential"},
	}, nil
}
