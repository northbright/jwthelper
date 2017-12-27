package jwthelper

import (
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// claims stores JWT claims.
// it contains a jwt.MapClaims.
type claims struct {
	m      sync.Mutex
	claims jwt.MapClaims
}

// Claim represents JWT claim.
// Use claim helper functions to get a Claim:
// StringClaim(), IntClaim(), UintClaim(), TimeClaim()...
type Claim struct {
	f func(ops *claims)
}

// newClaims news a Claims and intializes the internal mutext and map.
func newClaims() claims {
	return claims{
		sync.Mutex{},
		map[string]interface{}{},
	}
}

// newClaim news a Claim and set the internal map with given name -> value pair.
func newClaim(name string, value interface{}) Claim {
	return Claim{func(c *claims) {
		c.m.Lock()
		defer c.m.Unlock()
		c.claims[name] = value
	}}
}

// StringClaim returns a Claim with string value.
func StringClaim(name, value string) Claim {
	return newClaim(name, value)
}

// IntClaim returns a Claim with int value.
func IntClaim(name string, value int) Claim {
	return newClaim(name, value)
}

// Int32Claim returns a Claim with int32 value.
func Int32Claim(name string, value int32) Claim {
	return newClaim(name, value)
}

// Int64Claim returns a Claim with int64 value.
func Int64Claim(name string, value int64) Claim {
	return newClaim(name, value)
}

// UintClaim returns a Claim with uint value.
func UintClaim(name string, value uint) Claim {
	return newClaim(name, value)
}

// Uint32Claim returns a Claim with uint32 value.
func Uint32Claim(name string, value uint32) Claim {
	return newClaim(name, value)
}

// Uint64Claim returns a Claim with uint64 value.
func Uint64Claim(name string, value uint64) Claim {
	return newClaim(name, value)
}

// Float32Claim returns a Claim with float32 value.
func Float32Claim(name string, value float32) Claim {
	return newClaim(name, value)
}

// Float64Claim returns a Claim with float64 value.
func Float64Claim(name string, value float64) Claim {
	return newClaim(name, value)
}

// TimeClaim returns a Claim with time.Time value.
// It'll convert the time.Time to a Unix timestamp.
func TimeClaim(name string, value time.Time) Claim {
	return Int64Claim(name, value.Unix())
}
