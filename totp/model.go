package totp

import "github.com/parsidev/otp"

type ValidateOpts struct {
	Period    uint
	Digits    otp.Digits
	Algorithm otp.Algorithm
}
