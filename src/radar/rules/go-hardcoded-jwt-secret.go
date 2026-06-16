package main

import "github.com/golang-jwt/jwt/v4"

func bad(tokenStr string) {
	// ruleid: go-hardcoded-jwt-secret
	jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return []byte("my-hardcoded-secret"), nil
	})
}
