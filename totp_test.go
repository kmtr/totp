package totp

import (
	"testing"
	"time"
)

// https://tools.ietf.org/html/rfc6238
func TestGenerator_GenerateWithTime(t *testing.T) {
	sha1secret := "3132333435363738393031323334353637383930"
	sha256secret := "3132333435363738393031323334353637383930" + "313233343536373839303132"
	sha512secret := "3132333435363738393031323334353637383930" + "3132333435363738393031323334353637383930" + "3132333435363738393031323334353637383930" + "31323334"
	builder := &Generator{
		Digit:      8,
		StepSecond: 30,
	}
	type fields struct {
		Algorithm string
		SecretHex string
	}
	type args struct {
		t time.Time
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "dummy algorithm error",
			fields:  fields{"dummy", sha1secret},
			args:    args{time.Unix(1, 0)},
			wantErr: true,
		},
		{
			name:   "59 - sha1",
			fields: fields{"sha1", sha1secret},
			args:   args{time.Unix(59, 0)},
			want:   "94287082",
		},
		{
			name:   "59 - sha256",
			fields: fields{"sha256", sha256secret},
			args:   args{time.Unix(59, 0)},
			want:   "46119246",
		},
		{
			name:   "59 - sha512",
			fields: fields{"sha512", sha512secret},
			args:   args{time.Unix(59, 0)},
			want:   "90693936",
		},
		{
			name:   "1111111109 - sha1",
			fields: fields{"sha1", sha1secret},
			args:   args{time.Unix(1111111109, 0)},
			want:   "07081804",
		},
		{
			name:   "1111111109 - sha256",
			fields: fields{"sha256", sha256secret},
			args:   args{time.Unix(1111111109, 0)},
			want:   "68084774",
		},
		{
			name:   "1111111109 - sha512",
			fields: fields{"sha512", sha512secret},
			args:   args{time.Unix(1111111109, 0)},
			want:   "25091201",
		},
		{
			name:   "1111111111 - sha1",
			fields: fields{"sha1", sha1secret},
			args:   args{time.Unix(1111111111, 0)},
			want:   "14050471",
		},
		{
			name:   "1111111111 - sha256",
			fields: fields{"sha256", sha256secret},
			args:   args{time.Unix(1111111111, 0)},
			want:   "67062674",
		},
		{
			name:   "1111111111 - sha512",
			fields: fields{"sha512", sha512secret},
			args:   args{time.Unix(1111111111, 0)},
			want:   "99943326",
		},
		{
			name:   "1234567890 - sha1",
			fields: fields{"sha1", sha1secret},
			args:   args{time.Unix(1234567890, 0)},
			want:   "89005924",
		},
		{
			name:   "1234567890 - sha256",
			fields: fields{"sha256", sha256secret},
			args:   args{time.Unix(1234567890, 0)},
			want:   "91819424",
		},
		{
			name:   "1234567890 - sha512",
			fields: fields{"sha512", sha512secret},
			args:   args{time.Unix(1234567890, 0)},
			want:   "93441116",
		},
		{
			name:   "2000000000 - sha1",
			fields: fields{"sha1", sha1secret},
			args:   args{time.Unix(2000000000, 0)},
			want:   "69279037",
		},
		{
			name:   "2000000000 - sha256",
			fields: fields{"sha256", sha256secret},
			args:   args{time.Unix(2000000000, 0)},
			want:   "90698825",
		},
		{
			name:   "2000000000 - sha512",
			fields: fields{"sha512", sha512secret},
			args:   args{time.Unix(2000000000, 0)},
			want:   "38618901",
		},
		{
			name:   "20000000000 - sha1",
			fields: fields{"sha1", sha1secret},
			args:   args{time.Unix(20000000000, 0)},
			want:   "65353130",
		},
		{
			name:   "20000000000 - sha256",
			fields: fields{"sha256", sha256secret},
			args:   args{time.Unix(20000000000, 0)},
			want:   "77737706",
		},
		{
			name:   "20000000000 - sha512",
			fields: fields{"sha512", sha512secret},
			args:   args{time.Unix(20000000000, 0)},
			want:   "47863826",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Generator{
				Algorithm:  tt.fields.Algorithm,
				SecretHex:  tt.fields.SecretHex,
				StepSecond: builder.StepSecond,
				Digit:      builder.Digit,
			}
			got, err := o.GenerateWithTime(tt.args.t)
			if (err != nil) != tt.wantErr {
				t.Errorf("got error %v", err)
			} else {
				if got != tt.want {
					t.Errorf("Generator.GenerateWithTime() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestGenerator_Generate(t *testing.T) {
	type fields struct {
		Algorithm  string
		SecretHex  string
		StepSecond int64
		Digit      int
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "ok",
			fields: fields{
				Algorithm:  "sha1",
				SecretHex:  "abcdef",
				StepSecond: 30,
				Digit:      6,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Generator{
				Algorithm:  tt.fields.Algorithm,
				SecretHex:  tt.fields.SecretHex,
				StepSecond: tt.fields.StepSecond,
				Digit:      tt.fields.Digit,
			}
			got, err := o.Generate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Generator.OTP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == "" {
				t.Errorf("Generator.OTP() = %v", got)
			}
		})
	}
}
