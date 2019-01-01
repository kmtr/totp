package totp

import (
	"encoding/hex"
	"fmt"
	"math"
	"time"
)

type ErrorDecodeSecret error

type ErrorDecodeTimestamp error

func makeBinary(hash []byte, digit int) int {
	offset := hash[len(hash)-1] & 0xF
	binary := (int(hash[offset+0]&0x7F))<<24 |
		int((hash[offset+1]&0xFF))<<16 |
		int((hash[offset+2]&0xFF))<<8 |
		int((hash[offset+3]&0xFF))<<0
	return binary
}

type Generator struct {
	// HMACHashAlgorithm allows sha1, sha256, sha512
	HMACHashAlgorithm string
	Secret            []byte
	StepSecond        int64
	Digit             int
}

func (o *Generator) GenerateWithTime(timestamp time.Time) (string, error) {
	t := fmt.Sprintf("%016x", timestamp.Unix()/o.StepSecond)
	decodedTime, err := hex.DecodeString(t)
	if err != nil {
		return "", ErrorDecodeTimestamp(err)
	}
	code, err := makeHmac(o.HMACHashAlgorithm, o.Secret, decodedTime)
	if err != nil {
		return "", err
	}
	binary := makeBinary(code, o.Digit)
	p := int(math.Pow10(o.Digit))
	format := fmt.Sprintf("%%0%dd", o.Digit)
	return fmt.Sprintf(format, binary%p), nil
}

func (o *Generator) Generate() (string, error) {
	return o.GenerateWithTime(time.Now())
}
