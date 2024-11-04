package hotp

import (
	"github.com/parsidev/otp"
)

type ValidateOpts struct {
	Digits    otp.Digits
	Algorithm otp.Algorithm
}
