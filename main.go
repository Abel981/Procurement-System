package main

import (
	"context"
	"fmt"
	"procrument-system/configs"
	"procrument-system/routes"

	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()
	mongoClient :=	configs.ConnectDB()
	//routes
	routes.UserRoute(e)
	routes.AdminRoute(e)
	e.Logger.Fatal(e.Start(":1323"))

	defer func() {
		if err := mongoClient.Disconnect(context.Background()); err != nil {
			fmt.Println("hey")
			panic(err)
		}
	}()
}
