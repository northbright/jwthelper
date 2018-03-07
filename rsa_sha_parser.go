package jwthelper

import (
	"io/ioutil"

	"github.com/dgrijalva/jwt-go"
)

// NewRSASHAParser news a parser with RSA-SHA alg.
//
//     Params:
//         key: RSA public PEM key.
//         options: variadic options returned by option helper functions.
//                  e.g. ParserUseJSONNumber.
func NewRSASHAParser(key []byte, options ...ParserOption) *Parser {
	p := &Parser{
		nil,
		jwt.Parser{
			// UseJSONNumber will call encoding/json.Decoder.UseNumber().
			// It causes the Decoder to unmarshal a number into an interface{} as a Number instead of as a float64.
			// See https://godoc.org/encoding/json#Decoder.UseNumber
			UseJSONNumber: true,
			// If populated, only these methods will be considered valid
			// See https://godoc.org/github.com/dgrijalva/jwt-go#Parser
			ValidMethods: []string{
				jwt.SigningMethodRS256.Alg(),
				jwt.SigningMethodRS384.Alg(),
				jwt.SigningMethodRS512.Alg(),
			},
		},
	}

	// Override customized options.
	for _, op := range options {
		op.f(p)
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(key)
	if err != nil {
		return &Parser{}
	}

	p.key = publicKey
	return p
}

// NewRSASHAParserFromPEMFile news a parser with RSA-SHA alg from the RSA public PEM file.
//
//     Params:
//         key: RSA public PEM file path.
//         options: variadic options returned by option helper functions.
//                  e.g. ParserUseJSONNumber.
func NewRSASHAParserFromPEMFile(publicPEM string, options ...ParserOption) *Parser {
	key, err := ioutil.ReadFile(publicPEM)
	if err != nil {
		return &Parser{}
	}

	return NewRSASHAParser(key, options...)
}
