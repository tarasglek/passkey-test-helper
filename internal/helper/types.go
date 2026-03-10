package helper

type RegisterInput struct{}

type Credential struct {
	ID string `json:"id"`
}

type AttestationResponse struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type RegisterOutput struct {
	AttestationResponse AttestationResponse `json:"attestationResponse"`
	Credential          Credential          `json:"credential"`
}

type LoginInput struct{}

type AssertionResponse struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type LoginOutput struct {
	AssertionResponse AssertionResponse `json:"assertionResponse"`
	Credential        Credential        `json:"credential"`
}
