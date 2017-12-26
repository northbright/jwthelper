package jwthelper

import (
	"github.com/dgrijalva/jwt-go"
)

type Signer struct {
	Method jwt.SigningMethod
	key    interface{}
}

type SignerOption struct {
	f func(s *Signer)
}

func SignerMethod(m jwt.SigningMethod) SignerOption {
	return SignerOption{func(s *Signer) {
		s.Method = m
	}}
}

func NewRSASHASigner(privatePEM string, options ...SignerOption) *Signer {
	s := &Signer{
		// Default signing method: RSASHA-256.
		Method: jwt.SigningMethodRS256,
	}

	// Override customized options.
	for _, op := range options {
		op.f(s)
	}

	buf, err := ReadKey(privatePEM)
	if err != nil {
		return &Signer{}
	}

	if s.key, err = jwt.ParseRSAPrivateKeyFromPEM(buf); err != nil {
		return &Signer{}
	}

	return s
}

func (s *Signer) SignedString(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(s.Method, claims)
	return token.SignedString(s.key)
}
