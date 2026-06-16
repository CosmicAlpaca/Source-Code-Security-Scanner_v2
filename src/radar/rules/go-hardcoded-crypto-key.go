package main

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
)

// ruleid: go-hardcoded-crypto-key
func bad1() {
	hmac.New(sha256.New, []byte("super-secret-key-hardcoded"))
}

// ruleid: go-hardcoded-crypto-key
func bad2() {
	aes.NewCipher([]byte("hardcoded-aes-key"))
}

// ok: go-hardcoded-crypto-key
func good(key []byte) {
	hmac.New(sha256.New, key)
}
