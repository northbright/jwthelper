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
	// ErrInvalidAlg is the error of invalid alg.
	ErrInvalidAlg = fmt.Errorf("invalid alg")
)

// newSigner creates a signer with given signing method and signing key.
//
// m: signing method.
// key: signing key.
// use random bytes as key for jwt.SigningMethodHMAC.
// use PEM string as key for jwt.SigningMethodRSA, jwt.SigningMethodRSAPSS and jwt.SigningMethodECDSA.
func newSigner(m jwt.SigningMethod, key []byte) (*Signer, error) {
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

// NewSigner creates a signer with given "alg" header (RFC7518) and signing key.
//
// alg:
// See: https://tools.ietf.org/html/rfc7518#section-3.1
// "none" alg is not supported.
// key:
// use random bytes as key for "HS256", "HS384", "HS512".
// use private PEM string as key for "RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
// "PS256", "PS384", "PS512".
func NewSigner(alg string, key []byte) (*Signer, error) {
	m := jwt.GetSigningMethod(alg)
	if m == nil {
		return nil, ErrInvalidAlg
	}
	return newSigner(m, key)
}

// newSignerFromFile creates a signer with given signing method and signing key file.
func newSignerFromFile(m jwt.SigningMethod, f string) (*Signer, error) {
	key, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return newSigner(m, key)
}

// NewSignerFromFile creates a signer with given "alg" and signing key file.
func NewSignerFromFile(alg string, f string) (*Signer, error) {
	m := jwt.GetSigningMethod(alg)
	if m == nil {
		return nil, ErrInvalidAlg
	}
	return newSignerFromFile(m, f)
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
// claims: variadic Claim returned by claim helper functions.
// e.g. NewClaim("name", "frank"), NewClaim("count", 100)
// Return:
// signed string of JWT token.
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
