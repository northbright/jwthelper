package jwthelper

import (
	"bytes"
	"encoding/json"
	"fmt"
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

// Valid validates the parser.
func (p *Parser) Valid() bool {
	if p.key == nil {
		return false
	}
	return true
}

// Parse parses the signed string and returns the map which stores claims.
//
//     Params:
//         tokenString: token string to be parsed.
//     Return:
//         map stores claims.
//     comments:
//         by default, ParserUseJSONNumber option is true.
//         all numbers will be parsed to json.Number type.
//         Use Number.Int64(), Number.Float64(), Number.String() according to your need.
//         You may get float64 type if set ParserUseJSONNumber option to false when new a parser.
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
