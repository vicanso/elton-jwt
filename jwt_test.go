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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vicanso/elton"
)

func TestTTLToken(t *testing.T) {
	assert := assert.New(t)
	ttlToken := TTLToken{
		CookieName: "jwt",
		Secret:     []byte("abcd"),
	}
	data := "custom data"
	token, err := ttlToken.Encode(data)
	assert.Nil(err)

	result, err := ttlToken.Decode(token)
	assert.Nil(err)
	assert.Equal(data, result)

	c := elton.NewContext(httptest.NewRecorder(), nil)
	err = ttlToken.AddToCookie(c, map[string]string{
		"a": "1",
	})
	assert.Nil(err)
	assert.NotEmpty(c.GetHeader(elton.HeaderSetCookie))
}

func TestJWT(t *testing.T) {
	t.Run("token not found", func(t *testing.T) {
		assert := assert.New(t)
		req := httptest.NewRequest("GET", "/", nil)
		c := elton.NewContext(nil, req)
		fn := NewJWT(Config{
			Decode: func(data string) (string, error) {
				return "", nil
			},
		})
		err := fn(c)
		assert.Equal(ErrTokenNotFound, err)
	})

	t.Run("decode fail", func(t *testing.T) {
		token := &TTLToken{}
		cookieName := "jwt"
		conf := Config{
			Decode:     token.Decode,
			CookieName: cookieName,
		}

		assert := assert.New(t)
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  cookieName,
			Value: "abcd",
		})
		c := elton.NewContext(nil, req)
		c.Next = func() error {
			return nil
		}
		fn := NewJWT(conf)
		err := fn(c)
		assert.NotNil(err)
	})

	t.Run("get token from cookie", func(t *testing.T) {
		token := &TTLToken{
			TTL:    60 * time.Second,
			Secret: []byte("secret"),
		}
		cookieName := "jwt"
		conf := Config{
			Decode:     token.Decode,
			CookieName: cookieName,
		}

		data := "abcd"
		assert := assert.New(t)
		tokenString, err := token.Encode(data)
		assert.Nil(err)
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{
			Name:  cookieName,
			Value: tokenString,
		})
		c := elton.NewContext(nil, req)
		c.Next = func() error {
			return nil
		}
		fn := NewJWT(conf)
		err = fn(c)
		assert.Nil(err)
		assert.Equal(data, c.GetString(DefaultKey))
	})
}
