package jwthelper

import (
	"net/http"
	"time"
)

// CookieOption represent cookie option.
type CookieOption struct {
	f func(c *http.Cookie)
}

// CookieName returns the option for cookie name.
func CookieName(name string) CookieOption {
	return CookieOption{func(c *http.Cookie) {
		c.Name = name
	}}
}

// CookiePath returns the option for cookie path.
func CookiePath(path string) CookieOption {
	return CookieOption{func(c *http.Cookie) {
		c.Path = path
	}}
}

// CookieDomain returns the option for cookie domain.
func CookieDomain(domain string) CookieOption {
	return CookieOption{func(c *http.Cookie) {
		c.Domain = domain
	}}
}

// CookieExpires returns the option for cookie expires.
func CookieExpires(expires time.Time) CookieOption {
	return CookieOption{func(c *http.Cookie) {
		c.Expires = expires
	}}
}

// CookieMaxAge returns the option for cookie max age.
func CookieMaxAge(maxAge int) CookieOption {
	return CookieOption{func(c *http.Cookie) {
		c.MaxAge = maxAge
	}}
}

// CookieSecure returns the option for secure cookie.
func CookieSecure(secure bool) CookieOption {
	return CookieOption{func(c *http.Cookie) {
		c.Secure = secure
	}}
}

// CookieHttpOnly returns the option for HTTP only cookie.
func CookieHttpOnly(httpOnly bool) CookieOption {
	return CookieOption{func(c *http.Cookie) {
		c.HttpOnly = httpOnly
	}}
}

// NewCookie news a cookie contains JWT token.
//
//     Params:
//         tokenString: JWT token string. It'll be set as cookie value.
//         options: Cookie options(optional).
//                  Use helper functions to get options: CookieName(), CookieDomain()...
//     Comments:
//         It'll set cookie name to "jwt" if no name option specified.
func NewCookie(tokenString string, options ...CookieOption) *http.Cookie {
	cookie := http.Cookie{
		// Use "jwt" as cookie name by default.
		Name:     "jwt",
		Value:    tokenString,
		Secure:   true,
		HttpOnly: true,
	}

	// Override default cookie with customized options.
	for _, op := range options {
		op.f(&cookie)
	}

	return &cookie
}
