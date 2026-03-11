package helper

type RP struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type User struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type PubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type CreationOptions struct {
	Challenge        string             `json:"challenge"`
	RP               RP                 `json:"rp"`
	User             User               `json:"user"`
	PubKeyCredParams []PubKeyCredParam  `json:"pubKeyCredParams"`
}

type RegisterInput struct {
	Origin          string          `json:"origin"`
	CreationOptions CreationOptions `json:"creationOptions"`
}

type Credential struct {
	ID            string `json:"id"`
	UserID        string `json:"userId"`
	RPID          string `json:"rpId"`
	Algorithm     int    `json:"algorithm"`
	PublicKey     string `json:"publicKey"`
	PublicKeyPEM  string `json:"publicKeyPem"`
	PrivateKeyPEM string `json:"privateKeyPem"`
	SignCount     uint32 `json:"signCount"`
}

type AuthenticatorAttestationResponse struct {
	ClientDataJSON    string   `json:"clientDataJSON"`
	AttestationObject string   `json:"attestationObject"`
	AuthenticatorData string   `json:"authenticatorData"`
	PublicKey         string   `json:"publicKey"`
	PublicKeyAlgorithm int     `json:"publicKeyAlgorithm"`
	Transports        []string `json:"transports"`
}

type AttestationResponse struct {
	ID       string                         `json:"id"`
	RawID    string                         `json:"rawId"`
	Type     string                         `json:"type"`
	Response AuthenticatorAttestationResponse `json:"response"`
}

type RegisterOutput struct {
	AttestationResponse AttestationResponse `json:"attestationResponse"`
	Credential          Credential          `json:"credential"`
}

type RequestOptions struct {
	Challenge        string `json:"challenge"`
	RPID             string `json:"rpId"`
}

type LoginInput struct {
	Origin         string         `json:"origin"`
	RequestOptions RequestOptions `json:"requestOptions"`
	Credential     Credential     `json:"credential"`
}

type AuthenticatorAssertionResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	AuthenticatorData string `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle"`
}

type AssertionResponse struct {
	ID       string                         `json:"id"`
	RawID    string                         `json:"rawId"`
	Type     string                         `json:"type"`
	Response AuthenticatorAssertionResponse `json:"response"`
}

type LoginOutput struct {
	AssertionResponse AssertionResponse `json:"assertionResponse"`
	Credential        Credential        `json:"credential"`
}
