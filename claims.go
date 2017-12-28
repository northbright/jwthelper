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

// NewClaim news a Claim with given name -> value pair.
func NewClaim(name string, value interface{}) Claim {
	return Claim{func(c *claims) {
		c.m.Lock()
		defer c.m.Unlock()
		c.claims[name] = value
	}}
}

// TimeClaim returns a Claim with time.Time value.
// It'll convert the time.Time to a Unix timestamp.
func TimeClaim(name string, value time.Time) Claim {
	return NewClaim(name, value.Unix())
}
