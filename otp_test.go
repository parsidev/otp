package otp

import (
	"crypto/rand"
	"io"
	"testing"
)

func TestRandomKey(t *testing.T) {
	type args struct {
		length uint
		rand   io.Reader
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Test Random Key",
			args: args{
				length: 16,
				rand:   rand.Reader,
			},
			want:    "4GEM75XMUR4IJWFSZQAOBYGJLY",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RandomKey(tt.args.length, tt.args.rand)
			if (err != nil) != tt.wantErr {
				t.Errorf("RandomKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("RandomKey() got = %v, want %v", got, tt.want)
			}
		})
	}
}
