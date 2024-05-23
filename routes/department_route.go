package routes

import (
	"procrument-system/controllers"
	"github.com/labstack/echo/v4"
)

func DepartmentRoute(e *echo.Echo) {
	r := e.Group("/department")
    // r.POST("/signup", controllers.CreateUser) 
	r.POST("/login", controllers.LoginDepartment)
	r.POST("/logout", controllers.LogoutDepartment)
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

	// r.GET("/:id", controllers.GetAUser)
	r.POST("/createrequistion", controllers.CreateRequistion)
	r.GET("/requisitions/:deptAdminId", controllers.GetDepartmentRequistions)
	r.GET("/gigs", controllers.GetGigs)
	r.GET("/gig/:id", controllers.GetGigById)
	r.GET("/supplier/:id", controllers.GetAUser)
	
}