package main

import (
	"context"

	"procrument-system/authorization"
	"procrument-system/configs"
	"procrument-system/routes"

	"github.com/casbin/casbin"

	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()
	mongoClient := configs.ConnectDB()
	//routes
	routes.UserRoute(e)

	routes.AdminRoute(e)
	routes.DepartmentRoute(e)

	authEnforcer, _ := casbin.NewEnforcerSafe("./authorization/model.conf", "./authorization/policy.csv")

	enforcer := authorization.Enforcer{Enforcer: authEnforcer}

	e.Use(enforcer.Enforce)

	e.Logger.Fatal(e.Start(":1323"))

	defer func() {
		if err := mongoClient.Disconnect(context.Background()); err != nil {

			panic(err)
		}
	}()
}
