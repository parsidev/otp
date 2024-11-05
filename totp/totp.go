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

func GenerateCustomWithExpire(secret string, t time.Time, opts ValidateOpts) (passcode string, exp time.Time, err error) {
	if passcode, err = GenerateCodeCustom(secret, t, opts); err != nil {
		return "", time.Time{}, err
	}

	exp = time.Now().Add(time.Duration(opts.Period) * time.Second)

	exp = time.Date(exp.Year(), exp.Month(), exp.Day(), exp.Hour(), exp.Minute(), 0, 0, exp.Location())

	return passcode, exp, nil
}

func GenerateCodeCustom(secret string, t time.Time, opts ValidateOpts) (passcode string, err error) {
	if opts.Period == 0 {
		opts.Period = 30
	}

	co := cache.Get(secret)

	currentTime := time.Now().Unix()
	periodCounter := uint64(currentTime / int64(opts.Period))
	requestCounter := periodCounter + co
	t = time.Unix(int64(requestCounter*uint64(opts.Period)), 0)

	counter := uint64(math.Floor(float64(t.Unix()) / float64(opts.Period)))

	passcode, err = hotp.GenerateCodeCustom(secret, counter, hotp.ValidateOpts{
		Digits:    opts.Digits,
		Algorithm: opts.Algorithm,
	})

	if err != nil {
		return "", err
	}

	cache.Set(secret, co+1)

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
