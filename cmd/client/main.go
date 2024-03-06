package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"

	b64 "encoding/base64"

	"github.com/martinsaporiti/ed25519-poc/internal/dto"
)

func main() {
	publ, priv, _ := ed25519.GenerateKey((nil))
	client := &http.Client{}
	req, _ := http.NewRequest("GET", "http://localhost:3333/signIn", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer resp.Body.Close()

	challenge := dto.Challenge{}
	err = json.NewDecoder(resp.Body).Decode(&challenge)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(challenge.Message)
	digest := sha256.Sum256([]byte(challenge.Message))
	signature := ed25519.Sign(priv, digest[:])

	pk := b64.StdEncoding.EncodeToString(publ)
	sig := b64.StdEncoding.EncodeToString(signature)
	challengeResponse := dto.ChallengeResponse{
		Signature: sig,
		Message:   challenge.Message,
		PublicKey: pk,
	}

	challengeResponseJson, err := json.Marshal(challengeResponse)
	if err != nil {
		fmt.Println(err)
		return
	}

	req2, _ := http.NewRequest("POST", "http://localhost:3333/signIn", bytes.NewBuffer(challengeResponseJson))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Accept", "application/json")

	resp2, err := client.Do(req2)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		fmt.Println("error signing in")
		return
	}

	fmt.Println("signed successfully!!!")
}
