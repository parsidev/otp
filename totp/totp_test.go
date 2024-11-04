package totp

import (
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
