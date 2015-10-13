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
	SignKey   *[]byte           // Signing key.
	VerifyKey *[]byte           // Verifying key.
}

// KeyManager manages the keys by using kid(key id).
type KeyManager struct {
	Keys         map[string]*Key // Key map. Key: kid(key id), Value: Key Struct
	sync.RWMutex                 // Access map concurrently.
}

func ReadKey(keyFile string) (key *[]byte, err error) {
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

	return &buf, nil
}

func (km *KeyManager) setKey(kid string, key *Key) {
	km.Lock()
	km.Keys[kid] = key
	km.Unlock()
}

func (km *KeyManager) Get(kid string) (k *Key, err error) {
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

func (km *KeyManager) SetKeyFromFile(kid, alg, signKeyFile, verifyKeyFile string, isAsymmetricKey bool) (err error) {
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

	if isAsymmetricKey {
		if key.SignKey, err = ReadKey(signKeyFile); err != nil {
			return err
		}

		if key.VerifyKey, err = ReadKey(verifyKeyFile); err != nil {
			return err
		}
	} else {
		if key.SignKey, err = ReadKey(signKeyFile); err != nil {
			return err
		}
		key.VerifyKey = key.SignKey
	}

	km.setKey(kid, key)
	return nil
}

func (km *KeyManager) SetHS256Key(kid, keyFile string) (err error) {
	return km.SetKeyFromFile(kid, "HS256", keyFile, keyFile, false)
}

func (km *KeyManager) SetHS384Key(kid, keyFile string) (err error) {
	return km.SetKeyFromFile(kid, "HS384", keyFile, keyFile, false)
}

func (km *KeyManager) SetHS512Key(kid, keyFile string) (err error) {
	return km.SetKeyFromFile(kid, "HS512", keyFile, keyFile, false)
}

func (km *KeyManager) SetRS256Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return km.SetKeyFromFile(kid, "RS256", privKeyFile, pubKeyFile, true)
}

func (km *KeyManager) SetRS384Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return km.SetKeyFromFile(kid, "RS384", privKeyFile, pubKeyFile, true)
}

func (km *KeyManager) SetRS512Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return km.SetKeyFromFile(kid, "RS512", privKeyFile, pubKeyFile, true)
}

func (km *KeyManager) SetES256Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return km.SetKeyFromFile(kid, "ES256", privKeyFile, pubKeyFile, true)
}

func (km *KeyManager) SetES384Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return km.SetKeyFromFile(kid, "ES384", privKeyFile, pubKeyFile, true)
}

func (km *KeyManager) SetES512Key(kid, privKeyFile, pubKeyFile string) (err error) {
	return km.SetKeyFromFile(kid, "ES512", privKeyFile, pubKeyFile, true)
}
