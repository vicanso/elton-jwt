# elton-jwt

JWT middleware for elton.



```go
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/vicanso/elton"
	jwt "github.com/vicanso/elton-jwt"
)

func main() {
	e := elton.New()
	jwtCookie := "jwt"

	ttlToken := &jwt.TTLToken{
		TTL: 24 * time.Hour,
		// 密钥用于加密数据，需保密
		Secret: []byte("my secret"),
	}

	// Passthrough为false，会校验token是否正确
	jwtNormal := jwt.NewJWT(jwt.Config{
		CookieName: jwtCookie,
		TTLToken:   ttlToken,
	})
	// 用于初始化创建token使用（此时可能token还没有或者已过期)
	jwtPassthrough := jwt.NewJWT(jwt.Config{
		CookieName:  jwtCookie,
		TTLToken:    ttlToken,
		Passthrough: true,
	})

	e.GET("/login", jwtPassthrough, func(c *elton.Context) (err error) {
		// 模拟登录成功后获取用户信息
		c.Set(jwt.DefaultKey, `{"account":"tree.xie"}`)
		c.BodyBuffer = bytes.NewBufferString(`{"account":"tree.xie"}`)
		return
	})

	e.GET("/", jwtNormal, func(c *elton.Context) (err error) {
		// 获取相应的用户信息
		userInfo := c.GetString(jwt.DefaultKey)
		c.BodyBuffer = bytes.NewBufferString(userInfo)
		return
	})
	err := e.ListenAndServe(":3000")
	if err != nil {
		panic(err)
	}
}
```

