package jwthelper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

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
	ErrInvalidToken   = fmt.Errorf("invalid token")
	ErrInvalidPartNum = fmt.Errorf("invalid number of JWT part")
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

// newParser creates a parser with given signing method and verifying key.
//
// m: signing method.
// use random bytes as key for jwt.SigningMethodHMAC.
// use PEM string as key for jwt.SigningMethodRSA, jwt.SigningMethodRSAPSS and jwt.SigningMethodECDSA.
// for jwt.SigningMethodNone, key is ignored.
// options: variadic options returned by option helper functions.
// e.g. ParserUseJSONNumber.
func newParser(m jwt.SigningMethod, key []byte, options ...ParserOption) (*Parser, error) {
	var err error

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
				m.Alg(),
			},
		},
	}

	// Override customized options.
	for _, op := range options {
		op.f(p)
	}

	switch m.(type) {
	case *jwt.SigningMethodHMAC:
		p.key = key
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		if p.key, err = jwt.ParseRSAPublicKeyFromPEM(key); err != nil {
			return nil, err
		}
	case *jwt.SigningMethodECDSA:
		if p.key, err = jwt.ParseECPublicKeyFromPEM(key); err != nil {
			return nil, err
		}
	default:
		return nil, ErrInvalidSigningMethod
	}

	return p, nil
}

// NewParser creates a parser with given "alg"(RFC7518) and verifying key.
//
// alg:
// See: https://tools.ietf.org/html/rfc7518#section-3.1
// "none" alg is not supported.
// key:
// use random bytes as key for "HS256", "HS384", "HS512".
// use public PEM string as key for "RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
// "PS256", "PS384", "PS512".
func NewParser(alg string, key []byte, options ...ParserOption) (*Parser, error) {
	m := jwt.GetSigningMethod(alg)
	if m == nil {
		return nil, ErrInvalidAlg
	}
	return newParser(m, key, options...)
}

// newParserFromFile creates a parser with given signing method and verifying key file.
func newParserFromFile(m jwt.SigningMethod, f string, options ...ParserOption) (*Parser, error) {
	key, err := ioutil.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return newParser(m, key, options...)
}

// NewParserFromFile creates a parser with given "alg"(RFC7518) and verifying key file.
func NewParserFromFile(alg string, f string, options ...ParserOption) (*Parser, error) {
	m := jwt.GetSigningMethod(alg)
	if m == nil {
		return nil, ErrInvalidAlg
	}
	return newParserFromFile(m, f, options...)
}

// Valid validates the parser.
func (p *Parser) Valid() bool {
	if p.key == nil {
		return false
	}
	return true
}

// Parse parses the signed string and returns the map which stores claims.
//
// tokenString: token string to be parsed.
// Return:
// map stores claims.
// comments:
// by default, ParserUseJSONNumber option is true.
// all numbers will be parsed to json.Number type.
// Use Number.Int64(), Number.Float64(), Number.String() according to your need.
// You may get float64 type if set ParserUseJSONNumber option to false when new a parser.
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

func ParseClaims(tokenString string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidPartNum
	}

	buf, err := jwt.DecodeSegment(parts[1])
	if err != nil {
		return nil, err
	}

	m := map[string]interface{}{}
	dec := json.NewDecoder(bytes.NewBuffer(buf))
	if err = dec.Decode(&m); err != nil {
		return nil, err
	}

	return m, nil
}
