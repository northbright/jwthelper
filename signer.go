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
// Use option helper functions to set options:
// e.g. SigningMethod()
type SignerOption struct {
	f func(s *Signer)
}

var (
	// ErrInvalidSigner is the error of invalid signer.
	ErrInvalidSigner = fmt.Errorf("invalid signer")
)

// SigningMethod returns the option for signing method.
// It'll use jwt.SigningMethodRS256 by default if no signing method specified.
func SigningMethod(m jwt.SigningMethod) SignerOption {
	return SignerOption{func(s *Signer) {
		s.method = m
	}}
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
