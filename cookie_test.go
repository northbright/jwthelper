package jwthelper_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/northbright/jwthelper"
)

func doPostRequest(URL string) *http.Cookie {
	v := url.Values{}
	v.Set("username", "admin")
	v.Set("password", "admin")

	// Values.Encode() encodes the values into "URL encoded" form sorted by key.
	s := v.Encode()

	req, err := http.NewRequest("POST", URL, strings.NewReader(s))
	if err != nil {
		log.Printf("NewRequest error: %v", err)
		return nil
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	c := &http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		log.Printf("Do() error: %v", err)
		return nil
	}
	defer resp.Body.Close()

	// Get JWT cookie("jwt").
	cookies := resp.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "jwt" {
			log.Printf("After POST, JWT cookie: %v, resp: %v", cookie, resp)
			return cookie
		}
	}
	return nil
}

func doGetRequest(URL string, cookie *http.Cookie) {
	req, err := http.NewRequest("GET", URL, nil)
	if err != nil {
		log.Printf("NewRequest error: %v", err)
		return
	}
	// Add JWT cookie return by POST.
	req.AddCookie(cookie)

	c := &http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		log.Printf("Do() error: %v", err)
		return
	}
	defer resp.Body.Close()

	// Get response("admin").
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("ReadAll() error: %v", err)
		return
	}
	log.Printf("GET response: %v", string(buf))
}

func login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		cookie, err := r.Cookie("jwt")
		if err != nil {
			log.Printf("get JWT cookie error: %v", err)
			return
		}

		tokenString := cookie.Value
		parser, err := jwthelper.NewParser("RS256", []byte(rsaPubPEM))
		if err != nil {
			log.Printf("NewParser() error: %v", err)
			return
		}

		m, err := parser.Parse(tokenString)
		if err != nil {
			log.Printf("parser.Parse() error: %v", err)
			return
		}
		fmt.Fprintf(w, "hello, %v!", m["username"])

	case "POST":
		// Call ParseForm() to parse the raw query and update r.PostForm and r.Form.
		if err := r.ParseForm(); err != nil {
			return
		}

		// Post form from website
		username := r.FormValue("username")
		password := r.FormValue("password")
		if username == "admin" && password == "admin" {
			signer, err := jwthelper.NewSigner("RS256", []byte(rsaPrivPEM))
			if err != nil {
				log.Printf("NewSigner() error: %v", err)
				return
			}

			tokenString, err := signer.SignedString(
				jwthelper.NewClaim("username", username),
			)
			if err != nil {
				return
			}
			cookie := jwthelper.NewCookie(tokenString)
			http.SetCookie(w, cookie)
			fmt.Fprintf(w, "POST")
		}
	default:
		fmt.Fprintf(w, "Sorry, only GET and POST methods are supported.")
	}
}

func shutdownServer(srv *http.Server) {
	log.Printf("shutdown server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown server error: %v", err)
	}
	log.Println("shutdown server successfully")
}

func ExampleNewCookie() {
	log.Printf("\n\nExample of set / get JWT in cookie")

	mux := http.NewServeMux()
	mux.HandleFunc("/login", login)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	go func() {
		time.Sleep(1 * time.Second)
		cookie := doPostRequest("http://localhost:8080/login")
		if cookie != nil {
			doGetRequest("http://localhost:8080/login", cookie)
		}
		shutdownServer(srv)
	}()

	err := srv.ListenAndServe()
	if err != nil {
		if err == http.ErrServerClosed {
			log.Printf("server has been closed")
		} else {
			log.Printf("ListenAndServe() error: %s", err)
		}
	}

	// Output:
}
