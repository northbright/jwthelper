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

// SignerMethod returns the option for signing method.
// It'll use jwt.SigningMethodRS256 by default if no signing method specified.
func SignerMethod(m jwt.SigningMethod) SignerOption {
	return SignerOption{func(s *Signer) {
		s.method = m
	}}
}

// NewRSASHASigner new a signer with RSASHA alg.
//
//     Params:
//         key: RSA PEM key.
//         options: SignerOption returned by option helper functions.
//                  e.g. SignerMethod(jwt.SigningMethodRS512)
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

// NewRSASHASignerFromPEMFile new a signer with RSASHA alg from a private PEM file on disk.
//
//     Params:
//         privatePEM: RSA private PEM file path.
//         options: SignerOption returned by option helper functions.
//                  e.g. SignerMethod(jwt.SigningMethodRS512)
func NewRSASHASignerFromPEMFile(privatePEM string, options ...SignerOption) *Signer {
	key, err := ReadKey(privatePEM)
	if err != nil {
		return &Signer{}
	}

	return NewRSASHASigner(key, options...)
}

// Valid validates a signer.
func (s *Signer) Valid() bool {
	if s.method == nil || s.key == nil {
		return false
	}
	return true
}

// SignedString returns the signed string of the JWT token with given claims.
//
//     Params:
//         claims: variadic Claim returned by claim helper functions.
//                 e.g. StringClaim("name", "frank")
//                      IntClaim("count", 100)
//     Return:
//         signed string of JWT token.
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
