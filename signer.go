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

func NewRSASHASigner(signKey []byte, options ...SignerOption) *Signer {
	s := &Signer{
		// Default signing method: RSASHA-256.
		Method: jwt.SigningMethodRS256,
	}

	// Override customized options.
	for _, op := range options {
		op.f(s)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(signKey)
	if err != nil {
		return &Signer{}
	}

	s.key = privateKey
	return s
}

func NewRSASHASignerFromPEM(privatePEM string, options ...SignerOption) *Signer {
	buf, err := ReadKey(privatePEM)
	if err != nil {
		return &Signer{}
	}

	return NewRSASHASigner(buf, options...)
}

func (s *Signer) SignedString(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(s.Method, claims)
	return token.SignedString(s.key)
}
