// MIT License

// Copyright (c) 2020 Tree Xie

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package jwt

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/vicanso/elton"
	"github.com/vicanso/hes"
)

type (
	// Decode decode function
	Decode func(data string) (string, error)
	// Config jwt config
	Config struct {
		Key string
		// CookieName cookie for token
		CookieName string
		Skipper    elton.Skipper
		// Passthrough passthrough when token not found
		Passthrough bool
		// Decode decode
		Decode Decode
	}
	// TTLToken normal token
	TTLToken struct {
		TTL    time.Duration
		Secret []byte
	}
)

var (
	// ErrTokenNotFound err token not found
	ErrTokenNotFound = &hes.Error{
		Message:    "Token not found",
		StatusCode: http.StatusUnauthorized,
	}
	// ErrTokenIsInvalid err token is invalid
	ErrTokenIsInvalid = &hes.Error{
		Message:    "Token is invalid",
		StatusCode: http.StatusUnauthorized,
	}
)

const (
	// DefaultKey default key for data
	DefaultKey = "user"
)

// Encode ttl token encode
func (t *TTLToken) Encode(data string) (tokenString string, err error) {
	m := jwt.MapClaims{
		"_":   data,
		"exp": time.Now().Unix() + int64(t.TTL.Seconds()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, m)
	return token.SignedString(t.Secret)
}

// Decode ttl token decode
func (t *TTLToken) Decode(tokenString string) (data string, err error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			err := hes.New(fmt.Sprintf("Unexpected signing method: %v", token.Header["alg"]))
			return nil, err
		}
		return t.Secret, nil
	})
	if err != nil {
		return
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		data = claims["_"].(string)
	} else {
		err = ErrTokenIsInvalid
	}
	return
}

// NewJWT new jwt middleware
func NewJWT(config Config) elton.Handler {
	if config.Decode == nil {
		panic(errors.New("decode function can not be nil"))
	}
	skipper := config.Skipper
	if skipper == nil {
		skipper = elton.DefaultSkipper
	}
	key := config.Key
	if key == "" {
		key = DefaultKey
	}

	return func(c *elton.Context) (err error) {
		if skipper(c) {
			return c.Next()
		}
		var token string
		if config.CookieName != "" {
			token, err = getTokenFromCookie(c, config.CookieName)
		} else {
			token, err = getTokenFromHeader(c)
		}
		if err != nil {
			return
		}
		if token == "" && !config.Passthrough {
			err = ErrTokenNotFound
			return
		}
		if token != "" {
			data, err := config.Decode(token)
			if err != nil {
				return err
			}
			c.Set(key, data)
		}

		err = c.Next()
		if err != nil {
			return
		}
		return
	}
}
