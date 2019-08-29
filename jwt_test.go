// Copyright 2019 tree xie
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jwt

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vicanso/elton"
)

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
		assert.Equal(data, c.Get(DefaultKey).(string))
	})
}
