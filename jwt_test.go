package jwt_test

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/stevecallear/janice"

	jwtgo "github.com/dgrijalva/jwt-go"
	jwt "github.com/stevecallear/janice-jwt"
)

func init() {
	jwtgo.NoneSignatureTypeDisallowedError = nil
}

func ExampleNew() {
	key := []byte("secretkey")

	claims := map[string]interface{}{
		"sub": "test@email.com",
		"exp": time.Now().UTC().Add(1 * time.Hour),
	}

	token, err := jwtgo.NewWithClaims(jwtgo.SigningMethodHS512, jwtgo.MapClaims(claims)).SignedString(key)
	if err != nil {
		panic(err)
	}

	auth := jwt.New(jwt.HMAC(key))

	handler := auth.Then(func(w http.ResponseWriter, r *http.Request) error {
		c, _ := jwt.GetClaims(r)
		_, err := fmt.Fprint(w, c["sub"].(string))
		return err
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "Bearer "+token)

	handler.ServeHTTP(rec, req)

	fmt.Printf("%d %s", rec.Code, rec.Body)
	// Output: 200 test@email.com
}

func TestNew(t *testing.T) {
	now := time.Now().UTC()
	err := errors.New("expected")

	tests := []struct {
		name      string
		optionsFn func(*jwt.Options)
		handlerFn janice.HandlerFunc
		code      int
		claims    map[string]interface{}
		err       error
	}{
		{
			name: "should invoke the error func if the token is not set",
			optionsFn: func(o *jwt.Options) {
				o.TokenFn = func(*http.Request) (string, bool) {
					return "", false
				}
				o.KeyFn = func(*http.Request, *jwtgo.Token) (interface{}, error) {
					return nil, errors.New("key")
				}
				o.ErrorFn = func(http.ResponseWriter, error) error {
					return err
				}
			},
			handlerFn: func(w http.ResponseWriter, _ *http.Request) error {
				w.WriteHeader(http.StatusInternalServerError)
				return nil
			},
			code: http.StatusOK,
			err:  err,
		},
		{
			name: "should return an error if auth is not optional",
			optionsFn: func(o *jwt.Options) {
				o.TokenFn = func(*http.Request) (string, bool) {
					return "", false
				}
				o.KeyFn = func(*http.Request, *jwtgo.Token) (interface{}, error) {
					return nil, errors.New("key")
				}
				o.ErrorFn = func(http.ResponseWriter, error) error {
					return err
				}
			},
			handlerFn: func(w http.ResponseWriter, _ *http.Request) error {
				w.WriteHeader(http.StatusInternalServerError)
				return nil
			},
			code: http.StatusOK,
			err:  err,
		},
		{
			name: "should continue if auth is not required",
			optionsFn: func(o *jwt.Options) {
				o.Optional = true
				o.TokenFn = func(*http.Request) (string, bool) {
					return "", false
				}
				o.KeyFn = func(*http.Request, *jwtgo.Token) (interface{}, error) {
					return nil, errors.New("key")
				}
				o.ErrorFn = func(http.ResponseWriter, error) error {
					return errors.New("error")
				}
			},
			handlerFn: func(w http.ResponseWriter, _ *http.Request) error {
				w.WriteHeader(http.StatusInternalServerError)
				return nil
			},
			code: http.StatusInternalServerError,
		},
		{
			name: "should invoke the error func if the key is not set",
			optionsFn: func(o *jwt.Options) {
				o.TokenFn = func(*http.Request) (string, bool) {
					return newHMAC([]byte("secret"), map[string]interface{}{
						"sub": "subject",
						"exp": now.Add(1 * time.Hour).Unix(),
					}), true
				}
				o.KeyFn = func(*http.Request, *jwtgo.Token) (interface{}, error) {
					return nil, errors.New("key")
				}
				o.ErrorFn = func(http.ResponseWriter, error) error {
					return err
				}
			},
			handlerFn: func(w http.ResponseWriter, _ *http.Request) error {
				w.WriteHeader(http.StatusInternalServerError)
				return nil
			},
			code: http.StatusOK,
			err:  err,
		},
		{
			name: "should invoke the error func if the signing method is invalid",
			optionsFn: func(o *jwt.Options) {
				o.TokenFn = func(*http.Request) (string, bool) {
					return newNone(map[string]interface{}{
						"sub": "subject",
						"exp": now.Add(-1 * time.Hour).Unix(),
					}), true
				}
				o.KeyFn = func(*http.Request, *jwtgo.Token) (interface{}, error) {
					return []byte("secret"), nil
				}
				o.ErrorFn = func(http.ResponseWriter, error) error {
					return err
				}
			},
			handlerFn: func(w http.ResponseWriter, _ *http.Request) error {
				w.WriteHeader(http.StatusInternalServerError)
				return nil
			},
			code: http.StatusOK,
			err:  err,
		},
		{
			name: "should invoke the error func if the key is invalid",
			optionsFn: func(o *jwt.Options) {
				o.TokenFn = func(*http.Request) (string, bool) {
					return newHMAC([]byte("secret"), map[string]interface{}{
						"sub": "subject",
						"exp": now.Add(1 * time.Hour).Unix(),
					}), true
				}
				o.KeyFn = func(*http.Request, *jwtgo.Token) (interface{}, error) {
					return []byte("invalid"), nil
				}
				o.ErrorFn = func(http.ResponseWriter, error) error {
					return err
				}
			},
			handlerFn: func(w http.ResponseWriter, _ *http.Request) error {
				w.WriteHeader(http.StatusInternalServerError)
				return nil
			},
			code: http.StatusOK,
			err:  err,
		},

		{
			name: "should invoke the error func if the token is invalid",
			optionsFn: func(o *jwt.Options) {
				o.TokenFn = func(*http.Request) (string, bool) {
					return newHMAC([]byte("secret"), map[string]interface{}{
						"sub": "subject",
						"exp": now.Add(-1 * time.Hour).Unix(),
					}), true
				}
				o.KeyFn = func(*http.Request, *jwtgo.Token) (interface{}, error) {
					return []byte("secret"), nil
				}
				o.ErrorFn = func(http.ResponseWriter, error) error {
					return err
				}
			},
			handlerFn: func(w http.ResponseWriter, _ *http.Request) error {
				w.WriteHeader(http.StatusInternalServerError)
				return nil
			},
			code: http.StatusOK,
			err:  err,
		},
		{
			name: "should continue if the token is valid hmac",
			optionsFn: func(o *jwt.Options) {
				o.TokenFn = func(*http.Request) (string, bool) {
					return newHMAC([]byte("secret"), map[string]interface{}{
						"sub": "subject",
						"exp": now.Add(1 * time.Hour).Unix(),
					}), true
				}
				o.KeyFn = func(*http.Request, *jwtgo.Token) (interface{}, error) {
					return []byte("secret"), nil
				}
				o.ErrorFn = func(_ http.ResponseWriter, err error) error {
					return err
				}
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(http.StatusInternalServerError)
				return nil
			},
			claims: map[string]interface{}{
				"sub": "subject",
				"exp": float64(now.Add(1 * time.Hour).Unix()),
			},
			code: http.StatusInternalServerError,
		},
		{
			name: "should continue if the token is valid rsa",
			optionsFn: func(o *jwt.Options) {
				o.TokenFn = func(*http.Request) (string, bool) {
					return newRSA([]byte(rsaPrivateKey), map[string]interface{}{
						"sub": "subject",
						"exp": now.Add(1 * time.Hour).Unix(),
					}), true
				}
				o.KeyFn = func(*http.Request, *jwtgo.Token) (interface{}, error) {
					return jwtgo.ParseRSAPublicKeyFromPEM([]byte(rsaPublicKey))
				}
				o.ErrorFn = func(_ http.ResponseWriter, err error) error {
					return err
				}
			},
			handlerFn: func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(http.StatusInternalServerError)
				return nil
			},
			claims: map[string]interface{}{
				"sub": "subject",
				"exp": float64(now.Add(1 * time.Hour).Unix()),
			},
			code: http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withTime(now, func() {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest("GET", "/", nil)

				err := jwt.New(tt.optionsFn)(func(w http.ResponseWriter, r *http.Request) error {
					c, _ := jwt.GetClaims(r)
					if !reflect.DeepEqual(c, tt.claims) {
						t.Errorf("got %v, expected %v", c, tt.claims)
					}

					return tt.handlerFn(w, r)
				})(rec, req)
				if err != tt.err {
					t.Errorf("got %v, expected %v", err, tt.err)
				}

				if rec.Code != tt.code {
					t.Errorf("got %d, expected %d", rec.Code, tt.code)
				}
			})
		})
	}
}

func TestNewWithDefaultOptions(t *testing.T) {
	tests := []struct {
		name string
		auth *string
		code int
	}{
		{
			name: "should return unauthorized if the authorization header is not set",
			code: http.StatusUnauthorized,
		},
		{
			name: "should return unauthorized if the authorization header is empty",
			auth: strPtr(""),
			code: http.StatusUnauthorized,
		},
		{
			name: "should return unauthorized if the authorization header is invalid",
			auth: strPtr("basic credentials"),
			code: http.StatusUnauthorized,
		},
		{
			name: "should return unauthorized if the key fn is not set",
			auth: strPtr("Bearer " + newNone(map[string]interface{}{})),
			code: http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)

			if tt.auth != nil {
				req.Header.Set("Authorization", *tt.auth)
			}

			err := jwt.New()(func(w http.ResponseWriter, r *http.Request) error {
				return nil
			})(rec, req)
			if err != nil {
				t.Errorf("got %v, expected nil", err)
			}

			if rec.Code != tt.code {
				t.Errorf("got %d, expected %d", rec.Code, tt.code)
			}
		})
	}
}

func TestOptional(t *testing.T) {
	t.Run("should set optional to true", func(t *testing.T) {
		o := jwt.Options{}
		jwt.Optional(&o)

		if !o.Optional {
			t.Error("got false, expected true")
		}
	})
}

func TestHMAC(t *testing.T) {
	key := []byte("key")
	tests := []struct {
		name   string
		key    []byte
		method jwtgo.SigningMethod
		exp    interface{}
		err    bool
	}{
		{
			name:   "should return an error if the signing method is invalid",
			key:    key,
			method: jwtgo.SigningMethodRS256,
			err:    true,
		},
		{
			name:   "should return the token if the signing method is valid",
			key:    key,
			method: jwtgo.SigningMethodHS256,
			exp:    key,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := jwt.Options{}
			jwt.HMAC(tt.key)(&o)

			act, err := o.KeyFn(nil, jwtgo.New(tt.method))

			if err != nil && !tt.err {
				t.Errorf("got %v, expected nil", err)
			}

			if err == nil && tt.err {
				t.Error("got nil, expected an error")
			}

			if !reflect.DeepEqual(act, tt.exp) {
				t.Errorf("got %v, expected %v", act, tt.exp)
			}
		})
	}
}

func TestRSA(t *testing.T) {
	key, err := jwtgo.ParseRSAPublicKeyFromPEM([]byte(rsaPublicKey))
	if err != nil {
		panic(err)
	}
	tests := []struct {
		name   string
		key    *rsa.PublicKey
		method jwtgo.SigningMethod
		exp    interface{}
		err    bool
	}{
		{
			name:   "should return an error if the signing method is invalid",
			key:    key,
			method: jwtgo.SigningMethodHS256,
			err:    true,
		},
		{
			name:   "should return the token if the signing method is valid",
			key:    key,
			method: jwtgo.SigningMethodRS256,
			exp:    key,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := jwt.Options{}
			jwt.RSA(tt.key)(&o)

			act, err := o.KeyFn(nil, jwtgo.New(tt.method))

			if err != nil && !tt.err {
				t.Errorf("got %v, expected nil", err)
			}

			if err == nil && tt.err {
				t.Error("got nil, expected an error")
			}

			if !reflect.DeepEqual(act, tt.exp) {
				t.Errorf("got %v, expected %v", act, tt.exp)
			}
		})
	}
}

func newHMAC(k []byte, c map[string]interface{}) string {
	t, err := jwtgo.NewWithClaims(jwtgo.SigningMethodHS512, jwtgo.MapClaims(c)).SignedString(k)
	if err != nil {
		panic(err)
	}

	return t
}

func newRSA(k []byte, c map[string]interface{}) string {
	pk, err := jwtgo.ParseRSAPrivateKeyFromPEM(k)
	if err != nil {
		panic(err)
	}

	t, err := jwtgo.NewWithClaims(jwtgo.SigningMethodRS256, jwtgo.MapClaims(c)).SignedString(pk)
	if err != nil {
		panic(err)
	}

	return t
}

func newNone(c map[string]interface{}) string {
	t, err := jwtgo.NewWithClaims(jwtgo.SigningMethodNone, jwtgo.MapClaims(c)).SignedString(nil)
	if err != nil {
		panic(err)
	}

	return t
}

func withTime(t time.Time, fn func()) {
	tfn := jwtgo.TimeFunc

	defer func() {
		jwtgo.TimeFunc = tfn
	}()

	jwtgo.TimeFunc = func() time.Time {
		return t
	}

	fn()
}

func strPtr(s string) *string {
	return &s
}

const (
	rsaPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAzluOVwhb/fgP7RRcaBPIUEaTlV4FC75kfng4vQ6dS4mBCiB2
OzLPNG6+Vf5TfSpmBewsfINrSlc99fY+sgPCE+QIdS3byT3WRclcCyRAsieZs7Dy
kzL1d1wLykignAxn5izcXOkQbURMnofU1LPmiUkSFYySYharOELYpJvLV+hlvGN8
dOuPXEdGwboESQXVzWlywACmLdEgL+APgKV2OIvGAzynaX5fnicevcm8eQNV325G
2gjaekmrdDHmv0L6yFyh9yR1pafslpQX35zTKlmnhjIhZihOyfTb9cdkid4ButGx
TbkQhZR0eI+K3CqAf4Tk2HbKSaMjl+QXPDr7kwIDAQABAoIBAQCnjlPve0wm1aso
1+WIZLe75vKiz+rM9FVpE3kOmbVCxm3OqTkXLFRuwJUwAggMk8avfGtK1vLhNCGN
e9rAdKi7uebcLtZNezZnB+8C5PbbMaht7Xmp6DDEMCsqnvo6eyBKF5b+ogfCkTid
aLF53HGOe5SBhti9aKayUiTS0+Wyg/3FUmwvYY7/zxYjgg69WDb54CRCWtTc0TUT
Bw0LPu6DzBCvhvRD9l7gZLKeksUSnZtoCIQRmmdTglWn5dU7tGHpJQYHlXODqraB
JjVG72xyIp1NZheTgQEuj+p08DCgieGn0IDnATc+Z7yaZ9Q7UzeJGaevyVoJpnkT
BRC/UHSBAoGBAO53aAtpMdvXsfbv6aZ5aqDQbAv04jyBWIP8bgUJsl8GtpS06Gb4
+b9WcqHmo5E/g4fk4f1cAZ1Dur9A3A+xIGmpUBMAzY7qIuWyXYxkAsZCUbOZl+c8
4PZBeNvanqIy2qKnWAQDPrqTwQ4Fm59Zl4sYVTWvl1zrON1AlpePa9PhAoGBAN2H
xh8XL5UWippw+OkOfO0urf6SFjWai792dXTH9oRbZR5kWsHCESxgIGNip5ILD/4i
3NGbhBfc3je6eN3ZqTtMrfG+WrJPHN+AZ9CM3njaOBUZZMFzlT0JcjDw3CAxxAqj
lfX0f9QTN6bTdGSmL5y4TLVlqBXFBEOLKX7/7H3zAoGBAL6H4zayzyZzGXtOxyW+
/yYMQTfwak6jniCesR0PWVg5meoI/WNA7PMm1CJtkCT+VU5f3vy65YNM2Un0PZ/A
C0DBCfyU+KiGhGl4cOw6AEl+NZ9FSix05N19BF7NN1ArR6sL//P8z8LtSSO18ViJ
kd6OC48Ag/S28FE/SNNBwYqhAoGBAKxXWWmMlybsP24BH5PoAoZev1wB+KdBESEl
niD5A65aj+NB/V0phkS4j9nhwS2bz5hNNO8Yhn4uBO7j8e3dzItmjxg3l8WKSJMU
CS+0t8rbMbAwbjMVoW+3ro+mggnFzZbdRufui5fIT45IiQ9YPkg1FPA2Irq06ClH
1UOJBEnDAoGAQOfidq8W/ITrRaeBIXxLB9aAoIC7FPxPYdTOZilO6bNhTPQ5qY+c
g7TBOr7B7hC6kj7XSAYhcYmXPrYhzDdFia4O9ZJfKDgRLdmzuDxZGDK4hyBEraZz
JgzIE5E6gwiKHpiU+n7CwVGeeYT2vKWOSM+gluTmeD26zNhDY9udlGU=
-----END RSA PRIVATE KEY-----`

	rsaPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzluOVwhb/fgP7RRcaBPI
UEaTlV4FC75kfng4vQ6dS4mBCiB2OzLPNG6+Vf5TfSpmBewsfINrSlc99fY+sgPC
E+QIdS3byT3WRclcCyRAsieZs7DykzL1d1wLykignAxn5izcXOkQbURMnofU1LPm
iUkSFYySYharOELYpJvLV+hlvGN8dOuPXEdGwboESQXVzWlywACmLdEgL+APgKV2
OIvGAzynaX5fnicevcm8eQNV325G2gjaekmrdDHmv0L6yFyh9yR1pafslpQX35zT
KlmnhjIhZihOyfTb9cdkid4ButGxTbkQhZR0eI+K3CqAf4Tk2HbKSaMjl+QXPDr7
kwIDAQAB
-----END PUBLIC KEY-----`
)
