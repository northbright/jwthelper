package jwthelper

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/northbright/errorhelper"
	"github.com/northbright/pathhelper"
	"io/ioutil"
	"path"
	"path/filepath"
	"sync"
)

// Key struct consists of algorithm, signning key and verifying key.
type Key struct {
	Method    jwt.SigningMethod // jwt.SigningMethod
	SignKey   interface{}       // Signing key. HMAC: []byte, RSA: *crypto/rsa.PrivateKey, ECDSA: *crypto/ecdsa.PrivateKey.
	VerifyKey interface{}       // Verifying key. HMAC: []byte, RSA: *crypto/rsa.PublicKey, ECDSA: *crypto/ecdsa.PublicKey.
}

// JwtHelper manages the keys by using kid(key id).
type JwtHelper struct {
	Keys         map[string]*Key // Key map. Key: kid(key id), Value: Key Struct
	sync.RWMutex                 // Access map concurrently.
}

func ReadKey(keyFile string) (key []byte, err error) {
	if err := errorhelper.GenEmptyStringError(keyFile, "keyFile"); err != nil {
		return nil, err
	}

	// Make Abs key file path with current executable path if KeyFilePath is relative.
	p := ""
	if !filepath.IsAbs(keyFile) {
		dir := ""
		if dir, err = pathhelper.GetCurrentExecDir(); err != nil {
			return nil, err
		}
		p = path.Join(dir, keyFile)
	} else {
		p = keyFile
	}

	buf := []byte{}
	if buf, err = ioutil.ReadFile(p); err != nil {
		return nil, err
	}

	return buf, nil
}

func (h *JwtHelper) setKey(kid string, key *Key) {
	h.Lock()
	h.Keys[kid] = key
	h.Unlock()
}

func (h *JwtHelper) GetKey(kid string) (k *Key, err error) {
	if err := errorhelper.GenEmptyStringError(kid, "kid"); err != nil {
		return nil, err
	}

	h.RLock()
	k, ok := h.Keys[kid]
	h.RUnlock()

	if !ok {
		return nil, errorhelper.GenMapKeyNotFoundError(kid)
	}

	return k, nil
}

func (h *JwtHelper) SetKeyFromFile(kid, alg, signKeyFile, verifyKeyFile string) (err error) {
	key := &Key{}

	if err := errorhelper.GenEmptyStringError(kid, "kid"); err != nil {
		return err
	}

	if err := errorhelper.GenEmptyStringError(alg, "alg"); err != nil {
		return err
	}

	m := jwt.GetSigningMethod(alg)
	if m == nil {
		return errors.New(fmt.Sprintf("Incorrect alg: %s. Available algs: HS246,HS384,HS512,RS256,RS384,RS512,ES256,ES384,ES512", alg))
	}

	// Set Signing Method
	key.Method = m

	switch alg {
	case "HS256":
	case "HS384":
	case "HS512":
		if key.SignKey, err = ReadKey(signKeyFile); err != nil {
			return err
		}
		key.VerifyKey = key.SignKey

	case "RS256":
	case "RS384":
	case "RS512":
		buf := []byte{}
		if buf, err = ReadKey(signKeyFile); err != nil {
			return err
		}

		if key.SignKey, err = jwt.ParseRSAPrivateKeyFromPEM(buf); err != nil {
			return err
		}

		if buf, err = ReadKey(verifyKeyFile); err != nil {
			return err
		}

		if key.VerifyKey, err = jwt.ParseRSAPublicKeyFromPEM(buf); err != nil {
			return err
		}

	case "ES256":
	case "ES384":
	case "ES512":
		buf := []byte{}
		if buf, err = ReadKey(signKeyFile); err != nil {
			return err
		}

		if key.SignKey, err = jwt.ParseECPrivateKeyFromPEM(buf); err != nil {
			return err
		}

		if buf, err = ReadKey(verifyKeyFile); err != nil {
			return err
		}

		if key.VerifyKey, err = jwt.ParseECPublicKeyFromPEM(buf); err != nil {
			return err
		}
	default:
		return errors.New(fmt.Sprintf("Incorrect alg: %s. Available algs: HS246,HS384,HS512,RS256,RS384,RS512,ES256,ES384,ES512", alg))
	}

	h.setKey(kid, key)
	return nil
}

func (h *JwtHelper) SetHS256Key(kid, keyFile string) (err error) {
	return h.SetKeyFromFile(kid, "HS256", keyFile, keyFile)
}

func (h *JwtHelper) SetHS384Key(kid, keyFile string) (err error) {
	return h.SetKeyFromFile(kid, "HS384", keyFile, keyFile)
}

func (h *JwtHelper) SetHS512Key(kid, keyFile string) (err error) {
	return h.SetKeyFromFile(kid, "HS512", keyFile, keyFile)
}

func (h *JwtHelper) SetRS256Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return h.SetKeyFromFile(kid, "RS256", privKeyFile, pubKeyFile)
}

func (h *JwtHelper) SetRS384Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return h.SetKeyFromFile(kid, "RS384", privKeyFile, pubKeyFile)
}

func (h *JwtHelper) SetRS512Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return h.SetKeyFromFile(kid, "RS512", privKeyFile, pubKeyFile)
}

func (h *JwtHelper) SetES256Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return h.SetKeyFromFile(kid, "ES256", privKeyFile, pubKeyFile)
}

func (h *JwtHelper) SetES384Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return h.SetKeyFromFile(kid, "ES384", privKeyFile, pubKeyFile)
}

func (h *JwtHelper) SetES512Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return h.SetKeyFromFile(kid, "ES512", privKeyFile, pubKeyFile)
}

// CreateTokenString() creates a new JWT token string.
//
//   Params:
//       kid: Key id.
//       claims: map[string]interface{} to fill the jwt.Token[Claims].
//   Return:
//       tokenString: new created JWT token string.
//       err: error.
func (h *JwtHelper) CreateTokenString(kid string, claims map[string]interface{}) (tokenString string, err error) {
	var k *Key

	if err = errorhelper.GenEmptyStringError(kid, "kid"); err != nil {
		return "", err
	}

	if k, err = h.GetKey(kid); err != nil {
		return "", err
	}

	t := jwt.New(k.Method)
	t.Header["kid"] = kid
	t.Claims = claims
	return t.SignedString(k.SignKey)
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
func (h *JwtHelper) Parse(tokenString string) (kid string, claims map[string]interface{}, valid bool, err error) {
	t, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Header["kid"]; !ok {
			return nil, errorhelper.GenMapKeyNotFoundError("kid")
		}

		kid = ""
		if str, ok := token.Header["kid"].(string); !ok {
			msg := fmt.Sprintf("token.Header[\"kid\"]'s type is %T, but not string.", token.Header["kid"])
			return nil, errors.New(msg)
		} else {
			kid = str
		}

		key, err := h.GetKey(kid)
		if err != nil {
			return nil, err
		}

		return key.VerifyKey, nil
	})

	if err != nil {
		return "", nil, false, err
	}

	return kid, t.Claims, t.Valid, nil
}
