package jwthelper

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

type Signer struct {
	Method jwt.SigningMethod
	key    interface{}
}

type SignerOption struct {
	f func(s *Signer)
}

var (
	ErrInvalidSigner = fmt.Errorf("invalid signer")
)

func SignerMethod(m jwt.SigningMethod) SignerOption {
	return SignerOption{func(s *Signer) {
		s.Method = m
	}}
}

func NewRSASHASigner(key []byte, options ...SignerOption) *Signer {
	s := &Signer{
		// Default signing method: RSASHA-256.
		Method: jwt.SigningMethodRS256,
	}

	// Override customized options.
	for _, op := range options {
		op.f(s)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		return &Signer{}
	}

	s.key = privateKey
	return s
}

func NewRSASHASignerFromPEMFile(privatePEM string, options ...SignerOption) *Signer {
	key, err := ReadKey(privatePEM)
	if err != nil {
		return &Signer{}
	}

	return NewRSASHASigner(key, options...)
}

func (s *Signer) Valid() bool {
	if s.Method == nil || s.key == nil {
		return false
	}
	return true
}

func (s *Signer) SignedString(claims jwt.Claims) (string, error) {
	if !s.Valid() {
		return "", ErrInvalidSigner
	}

	token := jwt.NewWithClaims(s.Method, claims)
	return token.SignedString(s.key)
}
