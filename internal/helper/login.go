package helper

func LoginResponse(input LoginInput) (LoginOutput, error) {
	return LoginOutput{
		AssertionResponse: AssertionResponse{ID: input.Credential.ID, RawID: input.Credential.ID, Type: "public-key"},
		Credential:        input.Credential,
	}, nil
}
