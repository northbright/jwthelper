# jwthelper

[![Build Status](https://travis-ci.org/northbright/jwthelper.svg?branch=master)](https://travis-ci.org/northbright/jwthelper)
[![Go Report Card](https://goreportcard.com/badge/github.com/northbright/jwthelper)](https://goreportcard.com/report/github.com/northbright/jwthelper)
[![GoDoc](https://godoc.org/github.com/northbright/jwthelper?status.svg)](https://godoc.org/github.com/northbright/jwthelper)

#### About
jwthelper is a [Golang](https://golang.org/) package that provides [JWT(JSON Web Token)](https://en.wikipedia.org/wiki/JSON_Web_Token) functions based on [jwt-go](https://github.com/dgrijalva/jwt-go).

#### Use Case
* Users know all the keys up-front.

#### Features
* Simple Key Management Based on `kid(key ID)` of JWT Header
  * No need to write your own key lookup function
  * No [Critical Vulnerability](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/)

#### Example
* Set Key

        // Set key id and key pair for RSASSA-PKCS-v1_5 with SHA-256 hash algorithm.
        jwthelper.SetKeyFromFile("kid_001", "RS256", "./keys/RSA_2048_priv.pem", "./keys/RSA_2048_pub.pem")

        // Set key id and key for HMAC with SHA-256 hash algorithm.
        // HMAC using SHA-XXX is a symmetric key algorithm. It just read signKeyFile as secret key(verifyKeyFile is ignored). 
        jwthelper.SetKeyFromFile("kid_002", "HS256", "./keys/HMAC.key", "")
* Create JWT Token String

        // Set your own claims
        claims := make(map[string]interface{})
        claims["uid"] = "my_user_id"

        // Set kid
        kid := "kid_001"

        // Create JWT Token String
        if token, err := jwthelper.CreateTokenString(kid, claims); err != nil {
            fmt.Fprintf(os.Stderr, "CreateTokenString(%v, %v) error: %v\n", kid, claims, err)
        }

* Parse / Validate JWT Token String

        // Verify Token String
        if kid, claims, valid, err := jwthelper.Parse(token); err != nil {
            fmt.Fprintf(os.Stderr, "Parse(%v) error: %v\n", token, err)
        } else if !valid {
            fmt.Fprintf(os.Stderr, "Parse(%v) successfully but token is invalid\n", token)
        } else {
            fmt.Fprintf(os.Stderr, "Parse(%v) successfully.\nKid: %v, claims: %v, valid: %v\n", token, kid, claims, valid)
        }

#### Documentation
* [API Reference](http://godoc.org/github.com/northbright/jwthelper)

#### How to Generate Keys for JWT algs
* [Generate Keys for JWT algs](https://github.com/northbright/Notes/blob/master/jwt/generate_keys_for_jwt_alg.md)

#### Test
* To run test, please add -c parameter:  
  `go test -c && ./jwthelper.test`

#### Thanks
* [jwthelper](https://github.com/northbright/jwthelper) is based on [jwt-go(Dave Grijalva's powerful golang implemetion of JWT)](https://github.com/dgrijalva/jwt-go)  
  Many Thanks for Dave's [jwt-go](https://github.com/dgrijalva/jwt-go). 

#### License
* [MIT License](./LICENSE)
