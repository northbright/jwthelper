package jwthelper_test

import (
	"encoding/json"
	"log"

	"github.com/dgrijalva/jwt-go"
	"github.com/northbright/jwthelper"
)

func ExampleMultipleKeysSigner_SignedString() {
	// Example to show sign / parse JWT with multiple keys.

	// New a signer with RSA SHA-256 alg by given RSA private PEM key.
	s1 := jwthelper.NewRSASHASigner([]byte(rsaPrivPEM1))

	// New a signer with RSA SHA-512 alg by given RSA private PEM key.
	s2 := jwthelper.NewRSASHASigner([]byte(rsaPrivPEM1), jwthelper.SigningMethod(jwt.SigningMethodRS512))

	signer := jwthelper.NewMultipleKeysSigner()
	signer.Set("kid-for-api-1", s1)
	signer.Set("kid-for-vendor", s2)

	str, err := signer.SignedString(
		"kid-for-api-1",
		jwthelper.NewClaim("uid", "1"),
		jwthelper.NewClaim("count", 100),
	)

	if err != nil {
		log.Printf("SignedString() error: %v", err)
		return
	}
	log.Printf("SignedString() OK. str: %v", str)

	// New a parser.
	p1 := jwthelper.NewRSASHAParser([]byte(rsaPubPEM1))
	p2 := jwthelper.NewRSASHAParser([]byte(rsaPubPEM1))

	parser := jwthelper.NewMultipleKeysParser()
	parser.Set("kid-for-api-1", p1)
	parser.Set("kid-for-vendor", p2)

	mapClaims, err := parser.Parse(str)
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

	// Output:
}

var rsaPrivPEM1 string = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAn6MgLVWPxXqLfMRoCS2tXcRiJn/q+0h+Y2cNw0U0lQ6dIL5W
lFhr0C8YPHLDiGxe2AzMG0jj7QAvZnBKIQUA60WRoQ4MhS0mb66nqSZvPPfX74FN
Cdy7e0inW9CexBFKhW/UTI0PjF4Dl/fFdo5hcPTgeaPsiWWMoKVFdgDBfjYAnJvD
BzqYJfIZ61LrqIxrvHxmQ6ZoiLBc6ku2o6eHNYmwfMM82nQWrqPNZVCcCSQtD7+C
FiP4uNlTXIP9W436sDx+EsHI1HwEPFZA7Eb8shTV5s6Z4tfYYTs5873U2OF6DLCp
pOwSy2bvBzGamib9icZnXIkOv9v9Vf13lEhNAQIDAQABAoIBAFv1I/v5ZbBkPyXI
HgXrggqZrdBvr3TA9c1c99icbQXQPUM3Ybhilvh9qIBpu6lChAAAnzK4clN739Iq
rQkIUNc2ZAVaimvM7m83NO2DbmC4hHM7EJ21wWnrGD0Tl+Fp9HuZR7oxJ9u77GYG
HIGG0yq2ZPitLPyYusFvcuve05dXq2O+/RwQvmZ8zNzCx2foURTtA3ckYQJQyNg/
lYIWF/pY+VhsU5+BYilaf7JdjChjRkg3FH+pWrY2Mf2iKLPwS+5PnSBVfhqZCGqF
B9pm4KV350JX2g11GSysCaZJBXqsEntYaow1mENOwTq66uJHucIbh0KcL5PX5KEG
pLhJK+ECgYEAzVtiwXd1PVW35F3qwtSAszFZTLKIuHrGeAG4o1DSbpm6df3q16Xf
PTugw6VuAxRE/sqFBfvG+H7WWjNZkHiSEmoZAkAGsXWNyKM/XxI05SrhwBDmw+mw
aQib9PfgKb/otn39qwPjnjKw1eXSFxhMPYL52Reorf/DHWHIKbkSTscCgYEAxwFb
EYtWSm9657/AjobMInSw503nHMcbWP5vEcsT2RSPkdOZAVyVRagyxReD/2RpQL7f
Qrdfsn21O8CZpYkIYqsuF9fP/NexuZgFj49u1i7g+Y6FLoaIOVtMmw+YJm8pm2rS
M7UMw9kOmfYN8JD44pIS9h0km6oTZHo8GbsAXfcCgYBAyLqv9AKtddRMnABKtIVh
goj8dDpDkJ/6Dfj0tLOeJqs3PAKRQ4fYpm4CKrc5C3T0uGkcySAtFr6CuD5iIFdc
rdHz7sTtyPsQt8dvM6wyO8P6NprGZXu8tvWUY3p5UUyV/cs/3zs4lh9Ja3ZKyOSM
Zzxw61DQi6Y/J7Dg0Lzg0wKBgQCiYnvSPBWElaT/mBti8aF++CMmCw5sEBhDrRIq
vcALYdipELWIQ+jWNyJ+aurdqiyslVOOmB0xg5wwDsARMFk0UiRBdmuUENlH7UGU
XGD/yq7vVBle1o4v500CNl5b9ldIJ4kwgirRYLuma/4B7/n2v2VTiIJHtyct1QRX
ppztDwKBgQCLNHvLVvOKNweAear/Uk93h+PHp+HfweTy4yG1Xpj3A2BZKy/ySnSU
GtkJZpq5CaEA/U8UWpDXGS8U1KFhDeHSBJcVzF8zwGMxhcArWFcgHmj7jWVBYH89
Mj7aDzM8w/ey8p0vi+0KbQNeQSIUbiLnQD1Jj3k1mEU/FEPxuoulFg==
-----END RSA PRIVATE KEY-----

`

var rsaPubPEM1 string = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn6MgLVWPxXqLfMRoCS2t
XcRiJn/q+0h+Y2cNw0U0lQ6dIL5WlFhr0C8YPHLDiGxe2AzMG0jj7QAvZnBKIQUA
60WRoQ4MhS0mb66nqSZvPPfX74FNCdy7e0inW9CexBFKhW/UTI0PjF4Dl/fFdo5h
cPTgeaPsiWWMoKVFdgDBfjYAnJvDBzqYJfIZ61LrqIxrvHxmQ6ZoiLBc6ku2o6eH
NYmwfMM82nQWrqPNZVCcCSQtD7+CFiP4uNlTXIP9W436sDx+EsHI1HwEPFZA7Eb8
shTV5s6Z4tfYYTs5873U2OF6DLCppOwSy2bvBzGamib9icZnXIkOv9v9Vf13lEhN
AQIDAQAB
-----END PUBLIC KEY-----
`
