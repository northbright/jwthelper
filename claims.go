package jwthelper

import (
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Claims struct {
	m      sync.Mutex
	claims jwt.MapClaims
}

type Claim struct {
	f func(ops *Claims)
}

func NewClaims() Claims {
	return Claims{
		sync.Mutex{},
		map[string]interface{}{},
	}
}

func newClaim(name string, value interface{}) Claim {
	return Claim{func(c *Claims) {
		c.m.Lock()
		defer c.m.Unlock()
		c.claims[name] = value
	}}
}

func StringClaim(name, value string) Claim {
	return newClaim(name, value)
}

func IntClaim(name string, value int) Claim {
	return newClaim(name, value)
}

func Int32Claim(name string, value int32) Claim {
	return newClaim(name, value)
}

func Int64Claim(name string, value int64) Claim {
	return newClaim(name, value)
}

func UintClaim(name string, value uint) Claim {
	return newClaim(name, value)
}

func Uint32Claim(name string, value uint32) Claim {
	return newClaim(name, value)
}

func Uint64Claim(name string, value uint64) Claim {
	return newClaim(name, value)
}

func Float32Claim(name string, value float32) Claim {
	return newClaim(name, value)
}

func Float64Claim(name string, value float64) Claim {
	return newClaim(name, value)
}

func TimeClaim(name string, value time.Time) Claim {
	return Int64Claim(name, value.Unix())
}
