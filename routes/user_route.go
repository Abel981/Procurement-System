package routes

import (
	"procrument-system/controllers"

	"github.com/labstack/echo/v4"
)

func UserRoute(e *echo.Echo) {
    e.POST("user/signup", controllers.CreateUser) 
	e.GET("/user/:userId", controllers.GetAUser)
}