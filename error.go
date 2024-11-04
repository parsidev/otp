package otp

import "errors"

var (
	ErrValidateSecretInvalidBase32 = errors.New("decoding of secret as base32 failed")
	ErrValidateInputInvalidLength  = errors.New("input length unexpected")
	ErrGenerateMissingIssuer       = errors.New("issuer must be set")
	ErrGenerateMissingAccountName  = errors.New("account name must be set")
)
