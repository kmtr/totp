package totp

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
