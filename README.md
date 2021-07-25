# janice-jwt
[![Build Status](https://github.com/stevecallear/janice-jwt/actions/workflows/build.yml/badge.svg)](https://github.com/stevecallear/janice-jwt/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/stevecallear/janice-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/stevecallear/janice-jwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/stevecallear/janice-jwt)](https://goreportcard.com/report/github.com/stevecallear/janice-jwt)

janice-jwt provides JWT token middleware for use with [Janice](https://github.com/stevecallear/janice). It uses [jwt-go](https://github.com/dgrijalva/jwt-go) for token parsing and is similar in approach to [go-jwt-middleware](https://github.com/auth0/go-jwt-middleware) but as a `janice.MiddlewareFunc` implementation.


## Getting started
```
go get -u github.com/stevecallear/janice-jwt
```
```
package main

import (
	"fmt"
	"net/http"

	jwt "github.com/stevecallear/janice-jwt"
)

var key = []byte("secretkey")

func main() {
	auth := jwt.New(jwt.HMAC(key))

	handler := auth.Then(func(w http.ResponseWriter, r *http.Request) error {
		c, _ := jwt.GetClaims(r)
		_, err := fmt.Fprintf(w, c["sub"].(string))
		return err
	})

	http.ListenAndServe(":8080", handler)
}
```

## Token extraction
By default the middleware is configured to extract a bearer token from the request authorization header. This behaviour can be customised by replacing the options `TokenFn`. For example:
```
auth := jwt.New(jwt.HMAC(key), func(opt *jwt.Options) {
    opt.TokenFn = func(r *http.Request) (string, bool) {
        // return the extracted token and true if successful
    }
})
```

## Signing methods
The module supports HMAC and RSA signing keys using `jwt.HMAC` and `jwt.RSA` respectively. Other signing methods are supported by replacing the options `KeyFn`. For example, the following returns an ECDSA signing key:
```
// import jwtgo "github.com/dgrijalva/jwt-go"

auth := jwt.New(func(o *jwt.Options) {
    o.KeyFn = func(_ *http.Request, t *jwtgo.Token) (interface{}, error) {
        // validate the signing method
        if _, ok := t.Method.(*jwtgo.SigningMethodECDSA); !ok {
            return nil, fmt.Errorf("invalid signing method: %s", t.Header["alg"])
        }

        return key, nil
    }
})
```
The requests is included in the `KeyFn` signature to support request-specific keys.

## Error handling
Any errors extracting or parsing the token are handled by `ErrorFn`. By default this writes `http.StatusUnauthorized` to the response and returns `nil`. The behaviour can be customised to add logging or use error handling. The below example uses `strudel` to log and handle unauthorized errors:
```
auth := jwt.New(jwt.HMAC(key), func(opt *jwt.Options) {
    opt.ErrorFn = func(_ http.ResponseWriter, err error) error {
        return strudel.NewError(http.StatusText(http.StatusUnauthorized)).
            WithCode(http.StatusUnauthorized).
            WithLogField("err", err)
    }
})

chain := janice.New(strudel.ErrorHandling, auth)

handler := chain.Then(func(w http.ResponseWriter, r *http.Request) error {
    return nil
})
```

## Anonymous requests
Anonymous requests can be permitted using the `jwt.Optional` option. This ensures that the request will be handled if `TokenFn` does not return a value. If a token is returned, but cannot be parsed then `ErrorFn` will be invoked as per standard behaviour. For example:
```
auth := jwt.New(jwt.RSA(key), jwt.Optional)

handler := auth.Then(func(w http.ResponseWriter, r *http.Request) error {
    var err error

    if c, ok := jwt.GetClaims(r); ok {
        _, err = fmt.Fprint(w, c["sub"].(string))
    } else {
        _, err = fmt.Fprint(w, "anonymous")
    }

    return err
})
```