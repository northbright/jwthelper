package jwthelper

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/northbright/pathhelper"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"
)

// HMAC algorithm helper
type HMACHelper struct {
	Alg  string            // JWT HMAC algorithm: "HS256", "HS384", "HS512".
	Keys map[string][]byte // Map contains HMAC Keys. Key: key id('kid' of JWT header), Value: HMAC Key bytes.
}

// NewHMACHelper() creates a HMACHelper.
//
//   Params:
//     alg: JWT HMAC algorithm: "HS256", "HS384", "HS512".
//   Return:
//     h: *HMACHelper.
func NewHMACHelper(alg string) (h *HMACHelper) {
	h = &HMACHelper{"", map[string][]byte{}}

	algorithm := strings.ToUpper(alg)
	if algorithm != "HS256" && algorithm != "HS384" && algorithm != "HS512" {
		log.Fatalf("Alg is not one of HS256/HS384/HS512.")
	}

	h.Alg = algorithm
	return h
}

// SetKey() sets the HMAC key with key id.
//
//   Params:
//       kid: Key id. It's the 'kid' of JWT header.
//       keyFilePath: HMAC key file path. It can be relative or absolute path.
//   Example:
//       h.Set("1", "1stkey.dat")
//       h.Set("2", "2ndkey.dat")
func (h *HMACHelper) SetKey(kid string, keyFilePath string) {
	var err error

	if kid == "" {
		msg := "Empty kid."
		log.Fatalf("%s\n", msg)
	}

	if keyFilePath == "" {
		msg := "Empty key file path."
		log.Fatalf("%s\n", msg)
	}

	// Make Abs key file path with current executable path if KeyFilePath is relative.
	p := ""
	if !filepath.IsAbs(keyFilePath) {
		p, err = pathhelper.GetCurrentExecDir()
		if err != nil {
			msg := fmt.Sprintf("KeyFilePath err: %s", err)
			log.Fatalf("%s\n", msg)
		}
	} else {
		p = keyFilePath
	}

	if h.Keys[kid], err = ioutil.ReadFile(p); err != nil {
		msg := fmt.Sprintf("Read key file err: %s", err)
		log.Fatalf("%s\n", msg)
	}
}

// CreateTokenString() creates a token string.
func (h *HMACHelper) CreateTokenString(kid string, claims map[string]interface{}) (tokenString string, err error) {
	if kid == "" {
		msg := "Empty kid."
		log.Fatalf("%s\n", msg)
	}

	method := jwt.GetSigningMethod(h.Alg)
	t := jwt.New(method)
	t.Header["kid"] = kid
	t.Claims = claims
	return t.SignedString(h.Keys[kid])
}

// Parse() parses and validates the input token string.
//
//   Params:
//       tokenString: input JWT token string.
//   Return:
//       kid: Key id.
//       claims: map[string]interface{} to fill the jwt.Token[Claims].
//       valid: token is valid or not.
//       err: error.
func (h *HMACHelper) Parse(tokenString string) (kid string, claims map[string]interface{}, valid bool, err error) {
	t, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Header["kid"]; !ok {
			msg := "token.Header[\"kid\"] does not exist."
			log.Printf("%s\n", msg)
			return nil, errors.New(msg)
		}

		kid = ""
		if str, ok := token.Header["kid"].(string); !ok {
			msg := fmt.Sprintf("token.Header[\"kid\"]'s type is %T, but not string.", token.Header["kid"])
			log.Printf("%s\n", msg)
			return nil, errors.New(msg)
		} else {
			kid = str
		}

		if _, ok := h.Keys[kid]; !ok {
			msg := fmt.Sprintf("No HMAC key found for kid = %s", kid)
			log.Printf("%s\n", msg)
			return nil, errors.New(msg)
		}

		return h.Keys[kid], nil
	})

	if err != nil {
		return "", nil, false, err
	}

	return kid, t.Claims, t.Valid, nil
}
