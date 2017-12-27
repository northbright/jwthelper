package jwthelper

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

// Parser is used to parse JWT token string.
type Parser struct {
	key    interface{}
	parser jwt.Parser
}

// ParserOption represents the option for parsing JWT token string.
// Use option helper functions to set options:
// e.g. ParserUseJSONNumber()
type ParserOption struct {
	f func(p *Parser)
}

var (
	// ErrInvalidParser represents the error of invalid parser.
	ErrInvalidParser = fmt.Errorf("invalid parser")
	// ErrParseClaims represents the error of failed to parse claims.
	ErrParseClaims = fmt.Errorf("failed to parse claims")
	// ErrInvalidToken represents the error of invalid token.
	ErrInvalidToken = fmt.Errorf("invalid token")
)

// ParserUseJSONNumber returns the option for using JSON number.
// It causes the Decoder to unmarshal a number into an interface{} as a Number instead of as a float64.
// After calling Parser.Parse(), the type of number stored in the map[string]interface{} is:
// * float64: flag is false.
// * json.Number: flag is true.
// See https://godoc.org/encoding/json#Decoder.UseNumber
func ParserUseJSONNumber(flag bool) ParserOption {
	return ParserOption{func(p *Parser) {
		p.parser.UseJSONNumber = flag
	}}
}

// NewRSASHAParser news a parser with RSASHA alg.
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

// NewRSASHAParserFromPEMFile news a parser with RSASHA alg from the RSA public PEM file.
//
//     Params:
//         key: RSA public PEM file path.
//         options: variadic options returned by option helper functions.
//                  e.g. ParserUseJSONNumber.
func NewRSASHAParserFromPEMFile(publicPEM string, options ...ParserOption) *Parser {
	key, err := ReadKey(publicPEM)
	if err != nil {
		return &Parser{}
	}

	return NewRSASHAParser(key, options...)
}

// Valid validates the parser.
func (p *Parser) Valid() bool {
	if p.key == nil {
		return false
	}
	return true
}

func (p *Parser) Parse(tokenString string) (map[string]interface{}, error) {
	m := map[string]interface{}{}

	if !p.Valid() {
		return m, ErrInvalidParser
	}

	token, err := p.parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return p.key, nil
	})

	if err != nil {
		return m, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return m, ErrParseClaims
	}

	if !token.Valid {
		return m, ErrInvalidToken
	}

	return claims, nil
}
