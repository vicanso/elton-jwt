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

	"github.com/stretchr/testify/assert"
	"github.com/vicanso/elton"
)

func TestGetTokenFromCookie(t *testing.T) {
	name := "jwt"
	value := "abcd"
	assert := assert.New(t)
	req := httptest.NewRequest("GET", "/", nil)
	c := elton.NewContext(nil, req)
	token, err := getTokenFromCookie(c, name)
	assert.Nil(err)
	assert.Empty(token)

	req.AddCookie(&http.Cookie{
		Name:  name,
		Value: value,
	})
	token, err = getTokenFromCookie(c, name)
	assert.Nil(err)
	assert.Equal(value, token)
}

func TestGetTokenFromHeader(t *testing.T) {
	value := "abcd"
	assert := assert.New(t)
	req := httptest.NewRequest("GET", "/", nil)
	c := elton.NewContext(nil, req)
	token, err := getTokenFromHeader(c)
	assert.Nil(err)
	assert.Empty(token)

	c.SetRequestHeader("Authorization", value)
	_, err = getTokenFromHeader(c)
	assert.Equal(errAuthHeaderIsInvalid, err)

	c.SetRequestHeader("Authorization", "a "+value)
	_, err = getTokenFromHeader(c)
	assert.Equal(errAuthHeaderIsInvalid, err)

	c.SetRequestHeader("Authorization", "Bearer "+value)
	token, err = getTokenFromHeader(c)
	assert.Nil(err)
	assert.Equal(value, token)
}
