package routes

import (
	"procrument-system/controllers"
	"github.com/labstack/echo/v4"
)

func UserRoute(e *echo.Echo) {
    e.POST("/user/signup", controllers.CreateUser) 
	e.POST("/user/login", controllers.Login)
	// r := e.Group("/restricted")
	// Configure middleware with the custom claims type
	// config := echojwt.Config{
		
	// 	NewClaimsFunc: func(c echo.Context) jwt.Claims {
	// 		return new(JwtCustomClaims)
	// 	},
	// 	SigningKey: []byte("secret"),
	// 	TokenLookup: "header:Cookie:jwt=",
	// }
	// r.Use(echojwt.WithConfig(config))

	e.GET("/user/:id", controllers.GetAUser)
}