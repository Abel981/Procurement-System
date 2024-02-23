package routes

import (
	"fmt"
	"procrument-system/controllers"

	"github.com/golang-jwt/jwt/v4"
	// echojwt "github.com/labstack/echo-jwt"
	"github.com/labstack/echo/v4"
)
type Role string

const (
	MainAdmin       Role = "main admin"
	DepartmentAdmin Role = "department admin"
	User            Role = "user"
)

type JwtCustomClaims struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      Role   `json:"role"`
	jwt.RegisteredClaims
}
func UserRoute(e *echo.Echo) {
    e.POST("/user/signup", controllers.CreateUser) 
	e.POST("/user/login", controllers.Login)
	r := e.Group("/restricted")
	// Configure middleware with the custom claims type
	// config := echojwt.Config{
		
	// 	NewClaimsFunc: func(c echo.Context) jwt.Claims {
	// 		return new(JwtCustomClaims)
	// 	},
	// 	SigningKey: []byte("secret"),
	// 	TokenLookup: "header:Cookie:jwt=",
	// }
	// r.Use(echojwt.WithConfig(config))
	fmt.Println("what")
	r.GET("/user/:id", controllers.GetAUser)
}