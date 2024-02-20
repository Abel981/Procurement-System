package authorization

import (
	"github.com/casbin/casbin"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"procrument-system/controllers"
)

type Enforcer struct {
	Enforcer *casbin.Enforcer
  }

  func (e *Enforcer) Enforce(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*controllers.JwtCustomClaims)
	//   user, _, _ := c.Get("user").Cla
	  method := c.Request().Method
	  path := c.Request().URL.Path
  
	  result := e.Enforcer.Enforce(user, path, method)
  
	  if result {
		return next(c)
	  }
	  return echo.ErrForbidden
	}
  }