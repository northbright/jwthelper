package jwthelper

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

// Signer is used to sign JWT tokens.
// It stores signing method and key internally.
type Signer struct {
	method jwt.SigningMethod
	key    interface{}
}

// SignerOption represents the option for JWT token signing.
type SignerOption struct {
	f func(s *Signer)
}

var (
	// ErrInvalidSigner is the error of invalid signer.
	ErrInvalidSigner = fmt.Errorf("invalid signer")
)

func SignerMethod(m jwt.SigningMethod) SignerOption {
	return SignerOption{func(s *Signer) {
		s.method = m
	}}
}

func NewRSASHASigner(key []byte, options ...SignerOption) *Signer {
	s := &Signer{
		// Default signing method: RSASHA-256.
		method: jwt.SigningMethodRS256,
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
	if s.method == nil || s.key == nil {
		return false
	}
	return true
}

func (s *Signer) SignedString(claims ...Claim) (string, error) {
	if !s.Valid() {
		return "", ErrInvalidSigner
	}

	myClaims := newClaims()

	for _, claim := range claims {
		claim.f(&myClaims)
	}

	token := jwt.NewWithClaims(s.method, myClaims.claims)
	return token.SignedString(s.key)
}
