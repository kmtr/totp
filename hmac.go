package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
)

type ErrUnknownAlghorithm error

func makeHmac(alg string, key, msg []byte) ([]byte, error) {
	switch alg {
	case "sha1":
		return makeHmacSHA1(key, msg), nil
	case "sha256":
		return makeHmacSHA256(key, msg), nil
	case "sha512":
		return makeHmacSHA512(key, msg), nil
	}
	return nil, ErrUnknownAlghorithm(errors.New("unknown HMAC algorithm"))
}

func makeHmacSHA1(key, msg []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

func makeHmacSHA256(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

func makeHmacSHA512(key, msg []byte) []byte {
	mac := hmac.New(sha512.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}
