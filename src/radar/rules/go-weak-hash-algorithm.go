package main

import (
	"crypto/md5"
	"crypto/sha1"
)

func bad1(data []byte) {
	// ruleid: go-weak-hash-algorithm
	md5.Sum(data)
}

func bad2() {
	// ruleid: go-weak-hash-algorithm
	sha1.New()
}
