package jwthelper

import (
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
)

// NewRSASHASigner new a signer with RSA-SHA alg.
//
//     Params:
//         key: RSA PEM key.
//         options: variadic SignerOption returned by option helper functions.
//                  e.g. SigningMethod(jwt.SigningMethodRS512)
//                  If there's no signing method option specified, it's RSA-SHA-256 by default.
func NewRSASHASigner(key []byte, options ...SignerOption) *Signer {
	s := &Signer{
		// Default signing method: RSA-SHA-256.
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

// NewRSASHASignerFromPEMFile new a signer with RSA-SHA alg from a private PEM file on disk.
//
//     Params:
//         privatePEM: RSA private PEM file path.
//         options: SignerOption returned by option helper functions.
//                  e.g. SigningMethod(jwt.SigningMethodRS512)
//                  If there's no signing method option specified, it's RSA-SHA-256 by default.
func NewRSASHASignerFromPEMFile(privatePEM string, options ...SignerOption) *Signer {
	key, err := ioutil.ReadFile(privatePEM)
	if err != nil {
		return &Signer{}
	}

	return NewRSASHASigner(key, options...)
}
