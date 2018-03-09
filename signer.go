package jwthelper

import (
	"fmt"
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
)

// Signer is used to sign JWT tokens.
// It stores signing method and key internally.
type Signer struct {
	method jwt.SigningMethod
	key    interface{}
}

var (
	// ErrInvalidSigningMethod is the error of invalid signing method.
	ErrInvalidSigningMethod = fmt.Errorf("invalid signing method")
	// ErrInvalidSigner is the error of invalid signer.
	ErrInvalidSigner = fmt.Errorf("invalid signer")
)

// NewSigner creates a signer with given signing method and key.
func NewSigner(m jwt.SigningMethod, key []byte) (*Signer, error) {
	var err error
	s := &Signer{method: m}

	switch m.(type) {
	case *jwt.SigningMethodHMAC:
		s.key = key
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		if s.key, err = jwt.ParseRSAPrivateKeyFromPEM(key); err != nil {
			return nil, err
		}
	case *jwt.SigningMethodECDSA:
		if s.key, err = jwt.ParseECPrivateKeyFromPEM(key); err != nil {
			return nil, err
		}
	default:
		return nil, ErrInvalidSigningMethod
	}
	return s, nil
}

// NewSignerFromFile creates a signer with given signing method and key file.
func NewSignerFromFile(m jwt.SigningMethod, f string) (*Signer, error) {
	key, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return NewSigner(m, key)
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
