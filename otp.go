package otp

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"github.com/parsidev/otp/internal"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var Base32Encoder = base32.StdEncoding.WithPadding(base32.NoPadding)

var timeLocal *time.Location

func NewKeyFromURL(orig string) (*Key, error) {
	s := strings.TrimSpace(orig)

	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	return &Key{
		orig: s,
		url:  u,
	}, nil
}

func Generate(opts GenerateOpts) (*Key, error) {
	if opts.Issuer == "" {
		return nil, ErrGenerateMissingIssuer
	}

	if opts.AccountName == "" {
		return nil, ErrGenerateMissingAccountName
	}

	if opts.Rand == nil {
		opts.Rand = rand.Reader
	}

	if opts.SecretSize == 0 {
		opts.SecretSize = 16
	}

	if opts.Secret == "" {
		secret, err := RandomKey(opts.SecretSize, opts.Rand)
		if err != nil {
			return nil, err
		}

		opts.Secret = secret
	}

	if opts.Type == "" {
		opts.Type = TypeTotp
	}

	if opts.Period == 0 {
		opts.Period = 30
	}

	if opts.Digits == 0 {
		opts.Digits = DigitsSix
	}

	v := url.Values{}
	v.Set("secret", opts.Secret)
	v.Set("issuer", opts.Issuer)
	v.Set("algorithm", opts.Algorithm.String())
	v.Set("digits", opts.Digits.String())

	if opts.Type == TypeTotp {
		v.Set("period", strconv.FormatUint(uint64(opts.Period), 10))
	}

	u := url.URL{
		Scheme:   "otpauth",
		Host:     opts.Type.String(),
		Path:     fmt.Sprintf("/%v:%v", opts.Issuer, opts.AccountName),
		RawQuery: internal.EncodeQuery(v),
	}

	return NewKeyFromURL(u.String())
}

func RandomKey(length uint, rand io.Reader) (string, error) {
	secret := make([]byte, length)
	_, err := rand.Read(secret)
	if err != nil {
		return "", err
	}

	return Base32Encoder.EncodeToString(secret), nil
}

func SetLocal(loc *time.Location) {
	timeLocal = loc
	time.Local = loc
}

func GetLocal() *time.Location {
	return timeLocal
}
