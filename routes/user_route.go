package routes

import (
	"procrument-system/controllers"
	"github.com/labstack/echo/v4"
)

func UserRoute(e *echo.Echo) {
	r := e.Group("/user")
    r.POST("/signup", controllers.CreateUser) 
	r.POST("/login", controllers.LoginUser)
	r.POST("/logout", controllers.LogoutUser)
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

	r.GET("/:id", controllers.GetAUser)
	r.POST("/createbid", controllers.CreateBid)
	r.GET("/requistions", controllers.GetAllRequisitions)
	r.GET("/requistion/:id", controllers.GetRequisitionById)

}