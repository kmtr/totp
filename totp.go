package totp

import (
	"encoding/hex"
	"fmt"
	"math"
	"time"
)

type Decoder interface {
	DecodeString(s string) ([]byte, error)
}

type DecoderFunc func(s string) ([]byte, error)

func (d DecoderFunc) DecodeString(s string) ([]byte, error) {
	return d(s)
}

func SimpleDecode(s string) ([]byte, error) {
	return []byte(s), nil
}

type ErrorDecodeSecret error

type ErrorDecodeTimestamp error

type Generator struct {
	// HMACHashAlgorithm allows sha1, sha256, sha512
	HMACHashAlgorithm string
	Secret            []byte
	PeriodSeconds     int64
	Digits            int
}

func NewGenerator(alg string, period, digits int, secret []byte) *Generator {
	return &Generator{
		HMACHashAlgorithm: alg,
		Secret:            secret,
		PeriodSeconds:     int64(period),
		Digits:            digits,
	}
}

func (o *Generator) SetSecretString(decoder Decoder, secret string) error {
	s, err := decoder.DecodeString(secret)
	if err != nil {
		return err
	}
	o.Secret = s
	return nil
}

func makeBinary(hash []byte, digit int) int {
	offset := hash[len(hash)-1] & 0xF
	binary := (int(hash[offset+0]&0x7F))<<24 |
		int((hash[offset+1]&0xFF))<<16 |
		int((hash[offset+2]&0xFF))<<8 |
		int((hash[offset+3]&0xFF))<<0
	return binary
}

func (o *Generator) GenerateWithTime(timestamp time.Time) (string, error) {
	t := fmt.Sprintf("%016x", timestamp.Unix()/o.PeriodSeconds)
	decodedTime, err := hex.DecodeString(t)
	if err != nil {
		return "", ErrorDecodeTimestamp(err)
	}
	code, err := makeHmac(o.HMACHashAlgorithm, o.Secret, decodedTime)
	if err != nil {
		return "", err
	}
	binary := makeBinary(code, o.Digits)
	p := int(math.Pow10(o.Digits))
	format := fmt.Sprintf("%%0%dd", o.Digits)
	return fmt.Sprintf(format, binary%p), nil
}

func (o *Generator) Generate() (string, error) {
	return o.GenerateWithTime(time.Now())
}
