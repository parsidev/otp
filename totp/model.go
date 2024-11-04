package totp

import "github.com/parsidev/otp"

type ValidateOpts struct {
	Period    uint
	Skew      uint
	Digits    otp.Digits
	Algorithm otp.Algorithm
}
