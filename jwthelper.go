package jwthelper

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/northbright/errorhelper"
	"github.com/northbright/pathhelper"
	"io/ioutil"
	"net/http"
	"sync"
)

// Key struct consists of algorithm, signning key and verifying key.
type Key struct {
	Method    jwt.SigningMethod // jwt.SigningMethod
	SignKey   interface{}       // Signing key. HMAC: []byte, RSA: *crypto/rsa.PrivateKey, ECDSA: *crypto/ecdsa.PrivateKey.
	VerifyKey interface{}       // Verifying key. HMAC: []byte, RSA: *crypto/rsa.PublicKey, ECDSA: *crypto/ecdsa.PublicKey.
}

//  KeyManger manages the keys by using kid(key id).
type KeyManager struct {
	Keys         map[string]*Key // Key map. Key: kid(key id), Value: Key Struct
	sync.RWMutex                 // Access map concurrently.
}

var (
	km KeyManager = KeyManager{Keys: make(map[string]*Key)} // Internal key manager.
)

// ReadKey() reads key bytes from the key file.
func ReadKey(keyFile string) (key []byte, err error) {
	if err := errorhelper.GenEmptyStringError(keyFile, "keyFile"); err != nil {
		return nil, err
	}

	// Make Abs key file path with current executable path if KeyFilePath is relative.
	p := ""
	if p, err = pathhelper.GetAbsPath(keyFile); err != nil {
		return nil, err
	}

	buf := []byte{}
	if buf, err = ioutil.ReadFile(p); err != nil {
		return nil, err
	}

	return buf, nil
}

// setKey() sets the kid - Key pair.
//
//   Params:
//       kid: Key id. It should be unique.
//       key: Key struct.
func setKey(kid string, key *Key) {
	km.Lock()
	km.Keys[kid] = key
	km.Unlock()
}

// GetKey() return the key struct by given kid.
func GetKey(kid string) (k *Key, err error) {
	if err := errorhelper.GenEmptyStringError(kid, "kid"); err != nil {
		return nil, err
	}

	km.RLock()
	k, ok := km.Keys[kid]
	km.RUnlock()

	if !ok {
		return nil, errorhelper.GenMapKeyNotFoundError(kid)
	}

	return k, nil
}

// SetKeyFromFile() reads the keys from the key files then stores the unique kid - Key struct pair.
//
//   Params:
//       kid: Key id(unique).
//       alg: JWT alg.
//       signKeyFile: Signing key file.
//       verifyKeyFile: Verifying key file.
//   Return:
//       err: error.
func SetKeyFromFile(kid, alg, signKeyFile, verifyKeyFile string) (err error) {
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

	setKey(kid, key)
	return nil
}

// SetHS256Key() reads the HMAC SHA-256 key from key file and stores it with unique kid(key id).
//
// Key generation: github.com/northbright/keygen to generate HMAC SHA-XX key file.
func SetHS256Key(kid, keyFile string) (err error) {
	return SetKeyFromFile(kid, "HS256", keyFile, keyFile)
}

// SetHS384Key() reads the HMAC SHA-384 key from key file and stores it with unique kid(key id).
//
// Key generation: github.com/northbright/keygen to generate HMAC SHA-XX key file.
func SetHS384Key(kid, keyFile string) (err error) {
	return SetKeyFromFile(kid, "HS384", keyFile, keyFile)
}

// SetHS512Key() reads the HMAC SHA-512 key from key file and stores it with unique kid(key id).
//
// Key generation: github.com/northbright/keygen to generate HMAC SHA-XX key file.
func SetHS512Key(kid, keyFile string) (err error) {
	return SetKeyFromFile(kid, "HS512", keyFile, keyFile)
}

// SetRS256Key() reads the RSA SHA-256 keys from key files and stores it with unique kid(key id).
//
// Key generation: ssh-keygen -t rsa -b 2048
func SetRS256Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return SetKeyFromFile(kid, "RS256", privKeyFile, pubKeyFile)
}

// SetRS384Key() reads the RSA SHA-384 keys from key files and stores it with unique kid(key id).
//
// Key generation: ssh-keygen -t rsa -b 2048
func SetRS384Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return SetKeyFromFile(kid, "RS384", privKeyFile, pubKeyFile)
}

// SetRS512Key() reads the RSA SHA-512 keys from key files and stores it with unique kid(key id).
//
// Key generation: ssh-keygen -t rsa -b 2048
func SetRS512Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return SetKeyFromFile(kid, "RS512", privKeyFile, pubKeyFile)
}

// SetES256Key() reads the ECDSA(using P-256 curve and SHA-256) keys from key files and stores it with unique kid(key id).
//
// Key generation: ssh-keygen -t ecdsa -b 256
func SetES256Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return SetKeyFromFile(kid, "ES256", privKeyFile, pubKeyFile)
}

// SetES384Key() reads the ECDSA(using P-384 curve and SHA-384) keys from key files and stores it with unique kid(key id).
//
// Key generation: ssh-keygen -t ecdsa -b 384
func SetES384Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return SetKeyFromFile(kid, "ES384", privKeyFile, pubKeyFile)
}

// SetES512Key() reads the ECDSA(using P-521 curve and SHA-512) keys from key files and stores it with unique kid(key id).
//
// Key generation: ssh-keygen -t ecdsa -b 521(NOT 512)
func SetES512Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return SetKeyFromFile(kid, "ES512", privKeyFile, pubKeyFile)
}

// CreateTokenString() creates a new JWT token string.
//
//   Params:
//       kid: Key id.
//       claims: map[string]interface{} to fill the jwt.Token[Claims].
//   Return:
//       tokenString: new created JWT token string.
//       err: error.
func CreateTokenString(kid string, claims map[string]interface{}) (tokenString string, err error) {
	var k *Key

	if err = errorhelper.GenEmptyStringError(kid, "kid"); err != nil {
		return "", err
	}

	if k, err = GetKey(kid); err != nil {
		return "", err
	}

	t := jwt.New(k.Method)
	t.Header["kid"] = kid
	t.Claims = claims
	return t.SignedString(k.SignKey)
}

// jwt-go's KeyFunc type:
//
// type Keyfunc func(*Token) (interface{}, error)
func keyFunc(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Header["kid"]; !ok {
		return nil, errorhelper.GenMapKeyNotFoundError("kid")
	}

	kid := ""
	if str, ok := token.Header["kid"].(string); !ok {
		msg := fmt.Sprintf("token.Header[\"kid\"]'s type is %T, but not string.", token.Header["kid"])
		return nil, errors.New(msg)
	} else {
		kid = str
	}

	key, err := GetKey(kid)
	if err != nil {
		return nil, err
	}

	// Check signing method
	if token.Method.Alg() != key.Method.Alg() {
		return nil, errors.New("Signing Method Error.")
	}

	return key.VerifyKey, nil
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
func Parse(tokenString string) (kid string, claims map[string]interface{}, valid bool, err error) {
	t, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		return "", nil, false, err
	}

	return t.Header["kid"].(string), t.Claims, t.Valid, nil
}

// ParseFromRequest() parses and validates the input token string in an http.Request. It's a wrapper of jwt.ParseFromRequest().
//
//   Params:
//       r: http.Request may contain jwt token.
//   Return:
//       kid: Key id.
//       claims: map[string]interface{} to fill the jwt.Token[Claims].
//       valid: token is valid or not.
//       err: error.
func ParseFromRequest(r *http.Request) (kid string, claims map[string]interface{}, valid bool, err error) {
	t, err := jwt.ParseFromRequest(r, keyFunc)
	if err != nil {
		return "", nil, false, err
	}

	return t.Header["kid"].(string), t.Claims, t.Valid, nil
}
