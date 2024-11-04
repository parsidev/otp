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
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA256,
		},
	)
	return rv
}

func GenerateCode(secret string, t time.Time) (string, error) {
	return GenerateCodeCustom(secret, t, ValidateOpts{
		Period:    30,
		Skew:      1,
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
	}

	counter++
	cache.Set(secret, counter)

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

	var counters []uint64

	counter := cache.Get(secret)

	if counter == 0 {
		counter = uint64(math.Floor(float64(t.Unix()) / float64(opts.Period)))
	}

	counters = append(counters, counter)
	for i := 1; i <= int(opts.Skew); i++ {
		counters = append(counters, counter+uint64(i))
		counters = append(counters, counter-uint64(i))
	}

	for _, counter := range counters {
		rv, err := hotp.ValidateCustom(passcode, counter, secret, hotp.ValidateOpts{
			Digits:    opts.Digits,
			Algorithm: opts.Algorithm,
		})

		if err != nil {
			return false, err
		}

		if rv == true {
			return true, nil
		}
	}

	return false, nil
}
