package routes

import (
	"procrument-system/controllers"

	"github.com/labstack/echo/v4"
)

func AdminRoute(e *echo.Echo)  {
  e.POST("/admin/signup", controllers.CreateAdmin)
  e.POST("/admin/login", controllers.AdminLogin)
  e.POST("/admin/logout", controllers.AdminLogout)
  e.POST("/admin/createdepartment", controllers.AddDepartment)
  e.POST("/admin/createdepartmentadmin/:id",controllers.CreateDepartmentAdmin)
  e.GET("/admin/departments", controllers.GetAllDepartments)
  e.PATCH("/admin/updatedepartmentbudget/:id", controllers.UpdateDepartmentBudget)
  e.GET("/admin/getrequistions", controllers.GetAllRequisitions)
  e.GET("/admin/requistion/:id", controllers.GetRequisitionById)
  e.PATCH("/admin/approverequistion/:id", controllers.ApproveRequistion)
  e.DELETE("/admin/deleterequistion/:id", controllers.DeleteRequistion)
  e.PATCH("/admin/approvebid/:bidId", controllers.ApproveBid)

  e.GET("/admin/getbids/:reqId", controllers.GetAllBids)

}