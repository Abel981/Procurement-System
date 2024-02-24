package routes

import (
	"procrument-system/controllers"

	"github.com/labstack/echo/v4"
)

func AdminRoute(e *echo.Echo)  {
  e.POST("/admin/signup", controllers.CreateAdmin)
  e.POST("/admin/login", controllers.AdminLogin)
  e.POST("/admin/createdepartment", controllers.AddDepartment)
  e.PATCH("/admin/createdepartmentadmin/:id",controllers.CreateDepartmentAdmin)
  e.GET("/admin/getrequistions", controllers.GetAllRequisitions)
  e.PATCH("/admin/updaterequistion", controllers.ChangeRequistionStatus)

}