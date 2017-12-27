package jwthelper_test

import (
	"log"

	"github.com/dgrijalva/jwt-go"
	"github.com/northbright/jwthelper"
)

func ExampleSign_SignedString() {
	type MyClaims struct {
		UID string `json:"uid"` // User ID
		jwt.StandardClaims
	}

	privPEM := "keys/rsa-priv-2048.pem"
	s := jwthelper.NewRSASHASignerFromPEMFile(privPEM)

	claims := MyClaims{
		"1",
		jwt.StandardClaims{
			Issuer: "jwthelper",
		},
	}

	str, err := s.SignedString(claims)
	if err != nil {
		log.Printf("SignedString() error: %v", err)
		return
	}
	log.Printf("SignedString() OK. str: %v", str)
	// Output:
}
