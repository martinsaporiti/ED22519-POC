package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/martinsaporiti/ed25519-poc/internal/dto"
	"github.com/martinsaporiti/ed25519-poc/internal/jws"
)

func TestSignInHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/sigIn", nil)
	w := httptest.NewRecorder()
	signIn(w, req)
	res := w.Result()
	defer res.Body.Close()

	challenge := dto.Challenge{}

	err := json.NewDecoder(res.Body).Decode(&challenge)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	if res.StatusCode != http.StatusOK {
		t.Errorf("expected status code to be 200 got %d", res.StatusCode)
	}

	publ, priv, _ := ed25519.GenerateKey((nil))
	digest := sha256.Sum256([]byte(challenge.Message))
	signature := ed25519.Sign(priv, digest[:])

	t.Run("Test sign in with success ", func(t *testing.T) {
		pk := b64.StdEncoding.EncodeToString(publ)
		sig := b64.StdEncoding.EncodeToString(signature)
		challengeResponse := dto.ChallengeResponse{
			Signature: sig,
			Message:   challenge.Message,
			PublicKey: pk,
		}

		challengeResponseJson, err := json.Marshal(challengeResponse)
		if err != nil {
			t.Errorf("expected error to be nil got %v", err)
		}
		req2 := httptest.NewRequest(http.MethodPost, "/signIn", bytes.NewBuffer(challengeResponseJson))
		w2 := httptest.NewRecorder()
		signIn(w2, req2)
		res2 := w2.Result()
		defer res2.Body.Close()
		if res2.StatusCode != http.StatusOK {
			t.Errorf("expected status code to be 200 got %d", res2.StatusCode)
		}

		jwsPayload := dto.Jws{}
		json.NewDecoder(res2.Body).Decode(&jwsPayload)
		if jwsPayload.Token == "" {
			t.Errorf("expected token not to be empty got %s", jwsPayload.Token)
		}
		err = jws.Validate(jwsPayload.Token)
		if err != nil {
			t.Errorf("expected error to be nil got %v", err)
		}

	})

	t.Run("Test sign in with wrong signature ", func(t *testing.T) {
		pk := b64.StdEncoding.EncodeToString(publ)
		sig := b64.StdEncoding.EncodeToString([]byte("wrong sig"))
		challengeResponse := dto.ChallengeResponse{
			Signature: sig,
			Message:   challenge.Message,
			PublicKey: pk,
		}

		challengeResponseJson, err := json.Marshal(challengeResponse)
		if err != nil {
			t.Errorf("expected error to be nil got %v", err)
		}
		req2 := httptest.NewRequest(http.MethodPost, "/signIn", bytes.NewBuffer(challengeResponseJson))
		w2 := httptest.NewRecorder()
		signIn(w2, req2)
		res2 := w2.Result()
		defer res2.Body.Close()
		if res2.StatusCode == http.StatusOK {
			t.Errorf("expected status code not to be 200 got %d", res2.StatusCode)
		}
	})
}
