package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"runtime"
)

func Sha256Sum(message []byte) []byte {
	h := sha256.New()
	h.Write(message)
	return h.Sum(nil)
}

func Sha256SumString(message []byte) string {
	return fmt.Sprintf("%x", Sha256Sum(message))
}

func MustRandString(n int) string {
	s, err := RandString(n)
	if err != nil {
		panic(err)
	}
	return s
}

func RandString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := randReadFull(rand.Reader, buf); err != nil {
		return "", err
	}

	s := base64.RawURLEncoding.EncodeToString(buf)
	if len(s) < n {
		panic("invariant violation (impossible for base64 to compress)")
	}
	return s[:n], nil
}

func randReadFull(src io.Reader, buf []byte) (int, error) {
	n, err := io.ReadFull(src, buf)
	if err != nil {
		for i := 0; err != nil; i++ {
			n, err = io.ReadFull(src, buf)
			runtime.Gosched()
			if i > 1024 {
				return n, err
			}
		}
	}
	return n, err
}
