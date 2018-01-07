package jwthelper_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/northbright/jwthelper"
)

var (
	serverURL = "localhost:8080"
)

func doPostRequest(URL string) {
	v := url.Values{}
	v.Set("username", "admin")
	v.Set("password", "admin")

	// Values.Encode() encodes the values into "URL encoded" form sorted by key.
	s := v.Encode()

	req, err := http.NewRequest("POST", URL, strings.NewReader(s))
	if err != nil {
		log.Printf("NewRequest error: %v", err)
		return
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	c := &http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		log.Printf("Do() error: %v", err)
		return
	}
	defer resp.Body.Close()

	// Get Cookies
	cookies := resp.Cookies()
	log.Printf("After POST, cookies: %v, resp: %v", cookies, resp)
}

func login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		fmt.Fprintf(w, "GET")
	case "POST":
		// Call ParseForm() to parse the raw query and update r.PostForm and r.Form.
		if err := r.ParseForm(); err != nil {
			return
		}

		// Post form from website
		username := r.FormValue("username")
		password := r.FormValue("password")
		if username == "admin" && password == "admin" {
			signer := jwthelper.NewRSASHASigner([]byte(rsaPrivPEM))
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
	mux := http.NewServeMux()
	mux.HandleFunc("/login", login)

	srv := &http.Server{
		Addr:    serverURL,
		Handler: mux,
	}

	go func() {
		time.Sleep(1 * time.Second)
		doPostRequest("http://" + serverURL + "/login")
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
