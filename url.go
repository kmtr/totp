package totp

import (
	"net/url"
	"strconv"
	"strings"
)

type Encoder interface {
	EncodeToString(src []byte) string
}

type EncoderFunc func([]byte) string

func (e EncoderFunc) EncodeToString(src []byte) string {
	return e(src)
}

func SimpleEncode(src []byte) string {
	return string(src)
}

func (o *Generator) URL(secretEncoder Encoder, label, issuer string) string {
	base := "otpauth://totp/" + label + "?"
	val := url.Values{}
	val.Set("secret", secretEncoder.EncodeToString(o.Secret))
	if issuer != "" {
		val.Set("issuer", issuer)
	}
	val.Set("algorithm", strings.ToUpper(o.HMACHashAlgorithm))
	val.Set("digits", strconv.Itoa(o.Digits))
	val.Set("period", strconv.FormatInt(o.PeriodSeconds, 10))
	return base + val.Encode()
}
