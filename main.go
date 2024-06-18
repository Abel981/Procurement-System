package main

import (
	"context"
	"procrument-system/authorization"
	"procrument-system/configs"
	_ "procrument-system/docs"
	"procrument-system/routes"

	"github.com/casbin/casbin"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/echo/v4"
	echoSwagger "github.com/swaggo/echo-swagger"
)

//	@title			PROCUREMENT API
//	@version		1.0
//	@description	This is a sample procurement server api.
//	@license.name	Apache 2.0

func main() {
	e := echo.New()
	mongoClient := configs.ConnectDB()

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:3000", "http://127.0.0.1:3000"},
		AllowCredentials: true,
	}))
	//routes
	routes.UserRoute(e)

	routes.AdminRoute(e)

	routes.DepartmentRoute(e)

	authEnforcer, _ := casbin.NewEnforcerSafe("./authorization/model.conf", "./authorization/policy.csv")

	enforcer := authorization.Enforcer{Enforcer: authEnforcer}

	e.Use(enforcer.Enforce)
	e.GET("/swagger/*", echoSwagger.WrapHandler)

	e.Logger.Fatal(e.Start(":1323"))

	defer func() {
		if err := mongoClient.Disconnect(context.Background()); err != nil {

			panic(err)
		}
	}()
}
