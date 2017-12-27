package jwthelper

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

type Parser struct {
	key    interface{}
	parser jwt.Parser
}

type ParserOption struct {
	f func(p *Parser)
}

var (
	ErrInvalidParser = fmt.Errorf("invalid parser")
	ErrParseClaims   = fmt.Errorf("failed to parse claims")
	ErrInvalidToken  = fmt.Errorf("invalid token")
)

func ParserUseJSONNumber(flag bool) ParserOption {
	return ParserOption{func(p *Parser) {
		p.parser.UseJSONNumber = flag
	}}
}

func NewRSASHAParser(key []byte, options ...ParserOption) *Parser {
	p := &Parser{
		nil,
		jwt.Parser{
			// UseJSONNumber will use encoding/json.Decoder.UseNumber().
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

func NewRSASHAParserFromPEMFile(publicPEM string, options ...ParserOption) *Parser {
	key, err := ReadKey(publicPEM)
	if err != nil {
		return &Parser{}
	}

	return NewRSASHAParser(key, options...)
}

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
