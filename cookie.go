package jwthelper

import (
	"net/http"
	"time"
)

type CookieOption struct {
	f func(c *http.Cookie)
}

func CookieName(name string) CookieOption {
	return CookieOption{func(c *http.Cookie) {
		c.Name = name
	}}
}

func CookiePath(path string) CookieOption {
	return CookieOption{func(c *http.Cookie) {
		c.Path = path
	}}
}

func CookieDomain(domain string) CookieOption {
	return CookieOption{func(c *http.Cookie) {
		c.Domain = domain
	}}
}

func CookieExpires(expires time.Time) CookieOption {
	return CookieOption{func(c *http.Cookie) {
		c.Expires = expires
	}}
}

func CookieMaxAge(maxAge int) CookieOption {
	return CookieOption{func(c *http.Cookie) {
		c.MaxAge = maxAge
	}}
}

func CookieSecure(secure bool) CookieOption {
	return CookieOption{func(c *http.Cookie) {
		c.Secure = secure
	}}
}

func CookieHttpOnly(httpOnly bool) CookieOption {
	return CookieOption{func(c *http.Cookie) {
		c.HttpOnly = httpOnly
	}}
}

func NewCookie(tokenString string, options ...CookieOption) http.Cookie {
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

	return cookie
}
