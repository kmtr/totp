package totp

import (
	"encoding/hex"
	"fmt"
	"math"
	"time"
)

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
