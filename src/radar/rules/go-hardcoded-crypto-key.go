package main

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
)

func bad1() {
	// ruleid: go-hardcoded-crypto-key
	hmac.New(sha256.New, []byte("super-secret-key-hardcoded"))
}

func bad2() {
	// ruleid: go-hardcoded-crypto-key
	aes.NewCipher([]byte("hardcoded-aes-key"))
}

func good(key []byte) {
	// ok: go-hardcoded-crypto-key
	hmac.New(sha256.New, key)
}
