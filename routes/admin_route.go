package routes

import (
	"procrument-system/controllers"

	"github.com/labstack/echo/v4"
)

func AdminRoute(e *echo.Echo)  {
  e.POST("/admin/signup", controllers.CreateAdmin)
  // e.POST("/admin/login", controllers.AdminLogin)
  // e.POST("/admin/createdepartment", controllers.AddDepartment)
  // e.POST("/admin/createdepartmentadmin/:id",controllers.CreateDepartmentAdmin)
  // e.GET("/admin/getrequistions", controllers.GetAllRequisitions)
  // e.PATCH("/admin/updaterequistion/:id", controllers.ChangeRequistionStatus)
  // e.PATCH("/admin/approvebid/:bidId", controllers.ApproveBid)
  // e.GET("/admin/getbids/:reqId", controllers.GetAllBids)

}