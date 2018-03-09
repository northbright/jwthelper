package jwthelper_test

import (
	"encoding/json"
	"log"

	"github.com/dgrijalva/jwt-go"
	"github.com/northbright/jwthelper"
)

func ExampleMultipleKeysSigner_SignedString() {
	// Example to show sign / parse JWT with multiple keys.

	// New a signer with RSA SHA-384 alg by given RSA private PEM key.
	s2, err := jwthelper.NewSignerFromFile(jwt.SigningMethodRS384, "keys/rsa-priv-api.pem")
	if err != nil {
		log.Printf("NewSigner() error: %v", err)
		return
	}
	// New a multiple keys signer and set signers with "kid"(key id) which will be added to claims automatically.
	// We have RSA private key of API server but not have private key of vendor.
	signer := jwthelper.NewMultipleKeysSigner()
	signer.Set("kid-api", s2)

	str, err := signer.SignedString(
		"kid-api",
		jwthelper.NewClaim("uid", "2"),
		jwthelper.NewClaim("count", 200),
	)

	if err != nil {
		log.Printf("SignedString() error: %v", err)
		return
	}
	log.Printf("SignedString() OK. str: %v", str)

	// New parsers from public PEM file.
	p1, err := jwthelper.NewParserFromFile(jwt.SigningMethodRS256, "keys/rsa-pub-vendor.pem")
	if err != nil {
		log.Printf("NewParserFromFile() error: %v", err)
	}

	p2, err := jwthelper.NewParserFromFile(jwt.SigningMethodRS384, "keys/rsa-pub-api.pem")
	if err != nil {
		log.Printf("NewParserFromFile() error: %v", err)
	}

	// New a multiple keys parser and set parsers with "kid".
	parser := jwthelper.NewMultipleKeysParser()
	parser.Set("kid-vendor", p1)
	parser.Set("kid-api", p2)

	tokenStrs := []string{str, tokenStrSignedByVendor}

	for _, tokenStr := range tokenStrs {
		mapClaims, err := parser.Parse(tokenStr)
		if err != nil {
			log.Printf("Parse() error: %v", err)
			return
		}

		uid, ok := mapClaims["uid"]
		if !ok {
			log.Printf("uid not found")
			return
		}

		if _, ok = uid.(string); !ok {
			log.Printf("uid is not string type")
			return
		}

		count, ok := mapClaims["count"]
		if !ok {
			log.Printf("count not found")
			return
		}

		// It'll parse number as json.Number type by default.
		// Call Number.Int64(), Number.Float64(), Number.String() according to your need.
		// See https://godoc.org/encoding/json#Number
		num, ok := count.(json.Number)
		if !ok {
			log.Printf("count is not json.Number type: %T", count)
			return
		}

		n, err := num.Int64()
		if err != nil {
			log.Printf("convert json.Number to int64 error: %v", err)
			return
		}

		log.Printf("Parse() OK. uid: %v, count: %v, mapClaims: %v", uid, n, mapClaims)
	}
	// Output:
}

var tokenStrSignedByVendor string = `eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJjb3VudCI6MTAwLCJraWQiOiJraWQtdmVuZG9yIiwidWlkIjoiMSJ9.b5yqIYAeXMBpSexELGneELzSeCMWbKR_vUDaLiZvmWEv69GrHkytGDk1U-FjxUmoIU7-o8_qyh0StTV-R5okckChWdcdH5hWPIvgbxhI2uIHg4gVk3-BGdJn4nZAYNrk0CkUt-apvSH_0WZA8wlDcGRglpsWmqbD2X0k35VMLoA_boQsK6xzP2cHT3LHUcLVxE9pzC2kKxNho8wgDk9g76EPQ5S0ynso08lFDxOW7K1i8bOq6ZCfnzr98pMNlbcP-AuVqMqG94Ni1qpClnJXZ66CusVQ-cy-2eSnPaZkvlcPTZiQcBNZTPaf09vOXKaqbzWB1zHImbRiAi3EPYktnw`
