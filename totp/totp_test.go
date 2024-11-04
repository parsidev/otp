package totp

import (
	"github.com/parsidev/otp"
	"testing"
	"time"
)

func TestGenerateCode(t *testing.T) {
	type args struct {
		secret string
		t      time.Time
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Test TOTP",
			args: args{
				secret: "4GEM75XMUR4IJWFSZQAOBYGJLY",
				t:      time.Now().Local(),
			},
			want:    "680964",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateCode(tt.args.secret, tt.args.t)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GenerateCode() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateCodeCustom(t *testing.T) {
	type args struct {
		secret string
		t      time.Time
		opts   ValidateOpts
	}
	tests := []struct {
		name         string
		args         args
		wantPasscode string
		wantErr      bool
	}{
		{
			name: "Test Custom Code",
			args: args{
				secret: "4GEM75XMUR4IJWFSZQAOBYGJLY",
				t:      time.Now().Local(),
				opts: ValidateOpts{
					Period:    180,
					Digits:    otp.DigitsSix,
					Algorithm: otp.AlgorithmSHA1,
				},
			},
			wantPasscode: "",
			wantErr:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPasscode, err := GenerateCodeCustom(tt.args.secret, tt.args.t, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCodeCustom() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotPasscode != tt.wantPasscode {
				t.Errorf("GenerateCodeCustom() gotPasscode = %v, want %v", gotPasscode, tt.wantPasscode)
			}
		})
	}
}

func TestValidateCustom(t *testing.T) {
	type args struct {
		passcode string
		secret   string
		t        time.Time
		opts     ValidateOpts
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "Test Validation",
			args: args{
				passcode: "224027",
				secret:   "4GEM75XMUR4IJWFSZQAOBYGJLY",
				t:        time.Now().Local(),
				opts: ValidateOpts{
					Period:    180,
					Digits:    otp.DigitsSix,
					Algorithm: otp.AlgorithmSHA1,
				},
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateCustom(tt.args.passcode, tt.args.secret, tt.args.t, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCustom() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateCustom() got = %v, want %v", got, tt.want)
			}
		})
	}
}
