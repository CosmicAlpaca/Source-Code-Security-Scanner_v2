package main

import (
	"crypto/md5"
	"crypto/sha1"
)

// ruleid: go-weak-hash-algorithm
func bad1(data []byte) {
	md5.Sum(data)
}

// ruleid: go-weak-hash-algorithm
func bad2(data []byte) {
	sha1.New()
}
