package totp

import (
	"net/url"
	"testing"
)

func TestGenerator_URL(t *testing.T) {
	type fields struct {
		HMACHashAlgorithm string
		Secret            []byte
		PeriodSeconds     int64
		Digits            int
	}
	type args struct {
		label   string
		issuer  string
		encoder Encoder
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			name: "ok",
			fields: fields{
				HMACHashAlgorithm: "sha1",
				Secret:            []byte("1234567890"),
				PeriodSeconds:     15,
				Digits:            6,
			},
			args: args{
				encoder: EncoderFunc(SimpleEncode),
				issuer:  "gopher",
				label:   "susi",
			},
			want: "otpauth://totp/susi?secret=1234567890&issuer=gopher&algorithm=SHA1&digits=6&period=15",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Generator{
				HMACHashAlgorithm: tt.fields.HMACHashAlgorithm,
				Secret:            tt.fields.Secret,
				PeriodSeconds:     tt.fields.PeriodSeconds,
				Digits:            tt.fields.Digits,
			}
			got := o.URL(tt.args.encoder, tt.args.label, tt.args.issuer)
			gotURL, err := url.Parse(got)
			if err != nil {
				t.Error(err)
				return
			}
			gotURL.RawQuery = gotURL.Query().Encode()

			normalizeWant, err := url.Parse(tt.want)
			if err != nil {
				t.Error(err)
				return
			}
			normalizeWant.RawQuery = normalizeWant.Query().Encode()
			if gotURL.String() != normalizeWant.String() {
				t.Errorf("Generator.URL() = %v, want %v", gotURL.String(), normalizeWant.String())
			}
		})
	}
}
