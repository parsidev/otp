package totp

import (
	"github.com/parsidev/otp"
	"github.com/parsidev/otp/hotp"
	"github.com/parsidev/otp/internal/cache"
	"math"
	"time"
)

func Validate(passcode string, secret string) bool {
	rv, _ := ValidateCustom(
		passcode,
		secret,
		time.Now().Local(),
		ValidateOpts{
			Period:    30,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA256,
		},
	)
	return rv
}

func GenerateCode(secret string, t time.Time) (string, error) {
	return GenerateCodeCustom(secret, t, ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA256,
	})
}

func GenerateCodeCustom(secret string, t time.Time, opts ValidateOpts) (passcode string, err error) {
	if opts.Period == 0 {
		opts.Period = 30
	}

	counter := cache.Get(secret)

	if counter == 0 {
		counter = uint64(math.Floor(float64(t.Unix()) / float64(opts.Period)))
	} else {
		counter++
		cache.Set(secret, counter)
	}

	passcode, err = hotp.GenerateCodeCustom(secret, counter, hotp.ValidateOpts{
		Digits:    opts.Digits,
		Algorithm: opts.Algorithm,
	})

	if err != nil {
		return "", err
	}

	return passcode, nil
}

func ValidateCustom(passcode string, secret string, t time.Time, opts ValidateOpts) (bool, error) {
	if opts.Period == 0 {
		opts.Period = 30
	}

	counter := uint64(math.Floor(float64(t.Unix()) / float64(opts.Period)))

	rv, err := hotp.ValidateCustom(passcode, counter, secret, hotp.ValidateOpts{
		Digits:    opts.Digits,
		Algorithm: opts.Algorithm,
	})

	return err == nil && rv == true, err
}
