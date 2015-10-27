package jwthelper_test

import (
	"fmt"
	"github.com/northbright/jwthelper"
	"os"
)

type TestCase struct {
	Kid           string
	Alg           string
	SignKeyFile   string
	VerifyKeyFile string
	TokenString   string
}

var (
	testCases []TestCase = []TestCase{
		{Kid: "01", Alg: "HS256", SignKeyFile: "./keys/hmac.key", VerifyKeyFile: ""},
		{Kid: "02", Alg: "HS384", SignKeyFile: "./keys/hmac.key", VerifyKeyFile: ""},
		{Kid: "03", Alg: "HS512", SignKeyFile: "./keys/hmac.key", VerifyKeyFile: ""},
		{Kid: "04", Alg: "RS256", SignKeyFile: "./keys/rsa_2048_priv.pem", VerifyKeyFile: "./keys/rsa_2048_pub.pem"},
		{Kid: "05", Alg: "RS384", SignKeyFile: "./keys/rsa_2048_priv.pem", VerifyKeyFile: "./keys/rsa_2048_pub.pem"},
		{Kid: "06", Alg: "RS512", SignKeyFile: "./keys/rsa_2048_priv.pem", VerifyKeyFile: "./keys/rsa_2048_pub.pem"},
		{Kid: "07", Alg: "PS256", SignKeyFile: "./keys/rsa_2048_priv.pem", VerifyKeyFile: "./keys/rsa_2048_pub.pem"},
		{Kid: "08", Alg: "PS384", SignKeyFile: "./keys/rsa_2048_priv.pem", VerifyKeyFile: "./keys/rsa_2048_pub.pem"},
		{Kid: "09", Alg: "PS512", SignKeyFile: "./keys/rsa_2048_priv.pem", VerifyKeyFile: "./keys/rsa_2048_pub.pem"},
		{Kid: "10", Alg: "ES256", SignKeyFile: "./keys/ecdsa_256_priv.pem", VerifyKeyFile: "./keys/ecdsa_256_pub.pem"},
		{Kid: "11", Alg: "ES384", SignKeyFile: "./keys/ecdsa_384_priv.pem", VerifyKeyFile: "./keys/ecdsa_384_pub.pem"},
		{Kid: "12", Alg: "ES512", SignKeyFile: "./keys/ecdsa_521_priv.pem", VerifyKeyFile: "./keys/ecdsa_521_pub.pem"},
	}
)

// To run test, please add -c parameter:
// go test -c && ./jwthelper.test
func Example() {
	for i, v := range testCases {
		// Set Key with kid
		if err := jwthelper.SetKeyFromFile(v.Kid, v.Alg, v.SignKeyFile, v.VerifyKeyFile); err != nil {
			fmt.Fprintf(os.Stderr, "SetKeyFromFile(%v, %v, %v, %v) error: %v\n", v.Kid, v.Alg, v.SignKeyFile, v.VerifyKeyFile, err)
			return
		}

		// Set a uid claim for each alg
		claims := make(map[string]interface{})
		claims["uid"] = i + 1 // uid = kid

		// Creat token string
		if token, err := jwthelper.CreateTokenString(v.Kid, claims); err != nil {
			fmt.Fprintf(os.Stderr, "CreateTokenString(%v, %v) error: %v\n", v.Kid, claims, err)
			return
		} else {
			v.TokenString = token // Set token string
			fmt.Fprintf(os.Stderr, "CreateTokenString(%v, %v) successfully.\nAlg: %v, token: %v\n", v.Kid, claims, v.Alg, token)
		}

		// Verify Token String
		if kid, newClaims, valid, err := jwthelper.Parse(v.TokenString); err != nil {
			fmt.Fprintf(os.Stderr, "Parse(%v) error: %v\n", v.TokenString, err)
			return
		} else {
			fmt.Fprintf(os.Stderr, "Parse(%v) successfully.\nKid: %v, new claims: %v, valid: %v\n", v.TokenString, kid, newClaims, valid)
		}
	}

	// Test DeleteKey()
	kid := "12"
	if err := jwthelper.DeleteKey(kid); err != nil {
		fmt.Fprintf(os.Stderr, "DeleteKey(%v) error: %v\n", kid, err)
	}

	if _, err := jwthelper.GetKey(kid); err != nil {
		fmt.Fprintf(os.Stderr, "DeleteKey(%v) succeeded: %v.\n", kid, err)
	}

	// Output:
}
