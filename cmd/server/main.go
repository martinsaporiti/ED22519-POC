package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/martinsaporiti/ed25519-poc/internal/dto"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/signIn", signIn)
	fmt.Println("server started at port 3333")
	err := http.ListenAndServe(":3333", mux)
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("server closed\n")
	} else if err != nil {
		fmt.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}

}

func signIn(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")

		var clave [32]byte
		_, err := io.ReadFull(rand.Reader, clave[:])
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("error generating challenge"))
			return
		}
		challengeStr := hex.EncodeToString(clave[:])

		challenge := dto.Challenge{
			Message: challengeStr,
		}

		json, err := json.Marshal(challenge)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("error marshalling challenge"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(json)
	} else if r.Method == http.MethodPost {
		body := dto.ChallengeResponse{}
		err := json.NewDecoder(r.Body).Decode(&body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("error unmarshalling challenge response"))
			return
		}

		fmt.Println(body)

		m := []byte(body.Message)
		digest := sha256.Sum256(m)

		pk, _ := b64.StdEncoding.DecodeString(body.PublicKey)
		sig, _ := b64.StdEncoding.DecodeString(body.Signature)
		ok := ed25519.Verify(pk, digest[:], sig)
		if !ok {
			fmt.Println("signature does not verify")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("signature does not verify"))
			return
		}

		fmt.Println("signature verifies")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("signature verifies"))

	} else {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("method not allowed"))
	}
}
