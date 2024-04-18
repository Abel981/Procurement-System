package authorization

import (
	"fmt"
	"procrument-system/services"

	"github.com/casbin/casbin"

	// "procrument-system/controllers"

	// "github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type Enforcer struct {
	Enforcer *casbin.Enforcer
}

func (e *Enforcer) Enforce(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		fmt.Println(c.Path())
	
		if c.Path() == "/user/login" || c.Path() == "/user/signup" || c.Path() == "/admin/login" || c.Path() == "/admin/signup"  || c.Path() == "/department/login" || c.Path() == "/swagger/*"  {

			return next(c)
		}
		// fmt.Println(c.Cookie("jwt"))
		// 	cookie, err := c.Cookie("jwt")
		// 	fmt.Println(cookie.Value)
		// if err != nil {
		// 	return err
		// }
		jwtCookie, err := c.Cookie("jwt")
		if err != nil {
			return echo.ErrUnauthorized
		}

		err = services.VerifyToken(jwtCookie.Value)
		if err != nil {
			return echo.ErrUnauthorized
		}
		claims, err := services.ParseToken(jwtCookie.Value)
		if err != nil {
			return echo.ErrUnauthorized
		}
		fmt.Println(claims.Role)

		// user := c.Get("user").(*jwt.Token)
		// claims := user.Claims.(*controllers.JwtCustomClaims)
		method := c.Request().Method
		path := c.Request().URL.Path
		fmt.Println(path)

		result, err := e.Enforcer.EnforceSafe(string(claims.Role), path, method)
		if err != nil {

			return echo.ErrUnauthorized
		}

		if result {
			return next(c)
		}
		return echo.ErrForbidden
	}
}
