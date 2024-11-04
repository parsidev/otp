package otp

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"hash"
	"image"
	"io"
	"net/url"
	"strconv"
	"strings"
)

// -----------------------------------------------------

type Type string

const (
	TypeTotp Type = "totp"
	TypeHotp      = "hotp"
)

func (t Type) String() string {
	return string(t)
}

// -----------------------------------------------------

type Algorithm int

const (
	AlgorithmSHA1 Algorithm = iota
	AlgorithmSHA256
	AlgorithmSHA512
	AlgorithmMD5
)

func (a Algorithm) String() string {
	switch a {
	case AlgorithmSHA1:
		return "SHA1"
	case AlgorithmSHA256:
		return "SHA256"
	case AlgorithmSHA512:
		return "SHA512"
	case AlgorithmMD5:
		return "MD5"
	}
	panic("unreached")
}

func (a Algorithm) Hash() hash.Hash {
	switch a {
	case AlgorithmSHA1:
		return sha1.New()
	case AlgorithmSHA256:
		return sha256.New()
	case AlgorithmSHA512:
		return sha512.New()
	case AlgorithmMD5:
		return md5.New()
	}
	panic("unreached")
}

// -----------------------------------------------------

type Digits int

const (
	DigitsSix   Digits = 6
	DigitsEight Digits = 8
)

func (d Digits) Format(in int32) string {
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", d), in)
}

func (d Digits) Length() int {
	return int(d)
}

func (d Digits) String() string {
	return fmt.Sprintf("%d", d)
}

// -----------------------------------------------------

type Key struct {
	orig string
	url  *url.URL
}

func (k *Key) String() string {
	return k.orig
}

func (k *Key) Image(width int, height int) (image.Image, error) {
	b, err := qr.Encode(k.orig, qr.M, qr.Auto)
	if err != nil {
		return nil, err
	}

	b, err = barcode.Scale(b, width, height)

	if err != nil {
		return nil, err
	}

	return b, nil
}

func (k *Key) Type() string {
	return k.url.Host
}

func (k *Key) Issuer() string {
	q := k.url.Query()

	issuer := q.Get("issuer")

	if issuer != "" {
		return issuer
	}

	p := strings.TrimPrefix(k.url.Path, "/")
	i := strings.Index(p, ":")

	if i == -1 {
		return ""
	}

	return p[:i]
}

func (k *Key) AccountName() string {
	p := strings.TrimPrefix(k.url.Path, "/")
	i := strings.Index(p, ":")

	if i == -1 {
		return p
	}

	return p[i+1:]
}

func (k *Key) Secret() string {
	q := k.url.Query()

	return q.Get("secret")
}

func (k *Key) Period() uint64 {
	q := k.url.Query()

	if u, err := strconv.ParseUint(q.Get("period"), 10, 64); err == nil {
		return u
	}

	return 30
}

func (k *Key) Digits() Digits {
	q := k.url.Query()

	if u, err := strconv.ParseUint(q.Get("digits"), 10, 64); err == nil {
		switch u {
		case 8:
			return DigitsEight
		default:
			return DigitsSix
		}
	}

	return DigitsSix
}

func (k *Key) Algorithm() Algorithm {
	q := k.url.Query()

	a := strings.ToLower(q.Get("algorithm"))
	switch a {
	case "md5":
		return AlgorithmMD5
	case "sha256":
		return AlgorithmSHA256
	case "sha512":
		return AlgorithmSHA512
	default:
		return AlgorithmSHA1
	}
}

func (k *Key) URL() string {
	return k.url.String()
}

// -----------------------------------------------------

type GenerateOpts struct {
	Issuer      string
	AccountName string
	SecretSize  uint
	Secret      string
	Digits      Digits
	Algorithm   Algorithm
	Type        Type
	Rand        io.Reader
	Period      uint
}
