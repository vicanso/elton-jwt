# elton-jwt

JWT middleware for elton.



```go
package main

import (
	"net/http"
	"time"

	"github.com/vicanso/elton"
	jwt "github.com/vicanso/elton-jwt"
	responder "github.com/vicanso/elton-responder"
)

func main() {
	e := elton.New()
	jwtCookie := "jwt"
	e.Use(responder.NewDefault())

	ttlToken := &jwt.TTLToken{
		TTL: 24 * time.Hour,
		// 密钥用于加密数据，需保密
		Secret: []byte("my secret"),
	}

	// Passthrough为false，会校验token是否正确
	jwtNormal := jwt.NewJWT(jwt.Config{
		CookieName: jwtCookie,
		Decode:     ttlToken.Decode,
	})
	// 用于初始化创建token使用（此时可能token还没有或者已过期)
	jwtPassthrough := jwt.NewJWT(jwt.Config{
		CookieName:  jwtCookie,
		Decode:      ttlToken.Decode,
		Passthrough: true,
	})

	e.GET("/login", jwtPassthrough, func(c *elton.Context) (err error) {
		// 模拟登录成功后获取用户信息
		data, err := ttlToken.Encode(`{"account":"tree.xie"}`)
		if err != nil {
			return
		}
		// 将相关信息写入cookie
		err = c.AddCookie(&http.Cookie{
			Name:  jwtCookie,
			Value: data,
		})
		if err != nil {
			return
		}
		c.Body = map[string]string{
			"token": data,
		}
		return
	})

	e.GET("/", jwtNormal, func(c *elton.Context) (err error) {
		// 获取相应的用户信息
		userInfo := c.Get(jwt.DefaultKey).(string)
		c.Body = userInfo
		return
	})
	err := e.ListenAndServe(":3000")
	if err != nil {
		panic(err)
	}
}
```

