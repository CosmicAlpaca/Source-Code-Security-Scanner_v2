package main

import "github.com/golang-jwt/jwt/v4"

// ruleid: go-hardcoded-jwt-secret
func bad(tokenStr string) {
	jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return []byte("my-hardcoded-secret"), nil
	})
}
