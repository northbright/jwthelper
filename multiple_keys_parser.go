package jwthelper

import (
	"fmt"
)

type MultipleKeysParser struct {
	parsers map[string]*Parser
}

var (
	ErrInvalidMultipleKeysParser = fmt.Errorf("invalid multiple keys parser")
	ErrKIDNotFound               = fmt.Errorf("kid not found in claims")
	ErrKIDType                   = fmt.Errorf("invalid kid type(not string)")
	ErrParserNotFound            = fmt.Errorf("parser not found by kid")
)

func NewMultipleKeysParser() *MultipleKeysParser {
	return &MultipleKeysParser{
		parsers: map[string]*Parser{},
	}
}

func (p *MultipleKeysParser) Set(kid string, parser *Parser) {
	p.parsers[kid] = parser
}

func (p *MultipleKeysParser) Get(kid string) *Parser {
	parser := p.parsers[kid]

	return parser
}

func (p *MultipleKeysParser) Valid() bool {
	if p.parsers == nil {
		return false
	}
	return true
}

func (p *MultipleKeysParser) Parse(tokenString string) (map[string]interface{}, error) {
	if !p.Valid() {
		return nil, ErrInvalidMultipleKeysParser
	}

	// Just parse claims but not verify the signature.
	claims, err := ParseClaims(tokenString)
	if err != nil {
		return nil, err
	}

	// Get "kid".
	v, ok := claims["kid"]
	if !ok {
		return nil, ErrKIDNotFound
	}

	// Validate "kid" type == string.
	kid, ok := v.(string)
	if !ok {
		return nil, ErrKIDType
	}

	// Get parser according to "kid".
	parser, ok := p.parsers[kid]
	if !ok {
		return nil, ErrParserNotFound
	}

	return parser.Parse(tokenString)
}
