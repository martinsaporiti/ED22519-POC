package dto

type Challenge struct {
	Message string `json:"message"`
}

type ChallengeResponse struct {
	Signature string `json:"signature"`
	Message   string `json:"message"`
	PublicKey string `json:"publicKey"`
}
