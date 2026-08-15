package main

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashAdminPasswordPolicyAndConfirmation(t *testing.T) {
	tests := []struct {
		name         string
		password     []byte
		confirmation []byte
		want         string
	}{
		{"too short", bytes.Repeat([]byte{'a'}, minAdminPasswordBytes-1), bytes.Repeat([]byte{'a'}, minAdminPasswordBytes-1), "at least"},
		{"too long", bytes.Repeat([]byte{'a'}, maxAdminPasswordBytes+1), bytes.Repeat([]byte{'a'}, maxAdminPasswordBytes+1), "at most"},
		{"mismatch", []byte("correct horse battery staple"), []byte("correct horse battery staplf"), "does not match"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hashAdminPassword(tc.password, tc.confirmation)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestHashAdminPasswordProducesUsableBcryptHash(t *testing.T) {
	password := []byte("correct horse battery staple")
	hash, err := hashAdminPassword(password, append([]byte(nil), password...))
	if err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword(hash, password); err != nil {
		t.Fatalf("generated hash does not verify: %v", err)
	}
}
