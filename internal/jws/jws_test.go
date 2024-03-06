package jws

import "testing"

func TestGenerate(t *testing.T) {
	token, err := Generate()
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}

	err = Validate(token)
	if err != nil {
		t.Errorf("expected error to be nil got %v", err)
	}
}
