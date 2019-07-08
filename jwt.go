package jwt

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/stevecallear/janice"

	jwtgo "github.com/dgrijalva/jwt-go"
)

type (
	// Options represents a set of middleware options
	Options struct {
		Optional bool
		TokenFn  func(*http.Request) (string, bool)
		KeyFn    func(*http.Request, *jwtgo.Token) (interface{}, error)
		ErrorFn  func(http.ResponseWriter, error) error
	}

	contextKey string
)

var (
	defaultOptions = Options{
		TokenFn: func(r *http.Request) (string, bool) {
			h := r.Header.Get("Authorization")
			if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
				return "", false
			}

			t := strings.TrimSpace(h[7:])

			return t, len(t) > 0
		},
		KeyFn: func(*http.Request, *jwtgo.Token) (interface{}, error) {
			return nil, errors.New("key not set")
		},
		ErrorFn: func(w http.ResponseWriter, _ error) error {
			w.WriteHeader(http.StatusUnauthorized)

			return nil
		},
	}

	claimsKey = contextKey("claims")
)

// New returns new JWT middleware for the specified option funcs
func New(fns ...func(*Options)) janice.MiddlewareFunc {
	o := defaultOptions
	for _, fn := range fns {
		fn(&o)
	}

	return func(next janice.HandlerFunc) janice.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) error {
			t, ok := o.TokenFn(r)
			if !ok {
				if !o.Optional {
					return o.ErrorFn(w, errors.New("token not found"))
				}

				return next(w, r)
			}

			c := jwtgo.MapClaims{}
			_, err := jwtgo.ParseWithClaims(t, c, func(t *jwtgo.Token) (interface{}, error) {
				k, err := o.KeyFn(r, t)
				if err != nil {
					return nil, err
				}

				return k, nil
			})
			if err != nil {
				return o.ErrorFn(w, err)
			}

			return next(w, WithClaims(r, c))
		}
	}
}

// HMAC configures the middleware to use the specified HMAC key
func HMAC(k []byte) func(*Options) {
	return func(o *Options) {
		o.KeyFn = func(_ *http.Request, t *jwtgo.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwtgo.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("invalid signing method: %s", t.Header["alg"])
			}

			return k, nil
		}
	}
}

// RSA configures the middleware to use the specified RSA PEM key
func RSA(k *rsa.PublicKey) func(*Options) {
	return func(o *Options) {
		o.KeyFn = func(_ *http.Request, t *jwtgo.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwtgo.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("invalid signing method: %s", t.Header["alg"])
			}

			return k, nil
		}
	}
}

// Optional configures the middleware to allow unauthorized requests
func Optional(o *Options) {
	o.Optional = true
}

// GetClaims returns the claims for the specified request context
func GetClaims(r *http.Request) (map[string]interface{}, bool) {
	c, ok := r.Context().Value(claimsKey).(map[string]interface{})

	return c, ok
}

// WithClaims returns a copy of the request with the specified claims stored in the context
// The function is exported to simplify testing for apps that use GetClaims
func WithClaims(r *http.Request, c map[string]interface{}) *http.Request {
	ctx := context.WithValue(r.Context(), claimsKey, c)

	return r.WithContext(ctx)
}
