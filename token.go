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
	"strings"

	"github.com/vicanso/elton"
	"github.com/vicanso/hes"
)

var (
	errAuthHeaderIsInvalid = hes.New(`Bad Authorization header format. Format is "Authorization: Bearer <token>"`)
)

// getTokenFromCookie get token from cookie
func getTokenFromCookie(c *elton.Context, name string) (token string, err error) {
	cookie, _ := c.Cookie(name)
	if cookie == nil {
		return
	}
	token = cookie.Value
	return
}

// getTokenFromHeader get token from header
func getTokenFromHeader(c *elton.Context) (token string, err error) {
	value := c.GetRequestHeader("Authorization")
	if value == "" {
		return
	}
	arr := strings.Split(value, " ")
	if len(arr) == 2 {
		if strings.ToLower(arr[0]) == "bearer" {
			token = arr[1]
			return
		}
	}
	err = errAuthHeaderIsInvalid
	return
}
