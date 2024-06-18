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
  e.GET("/admin/department/:id", controllers.GetDepartmentById)
e.DELETE("/admin/deletedeptadmin/:id", controllers.DeleteDepartmentAdmin)
  e.PATCH("/admin/updatedepartmentbudget/:id", controllers.UpdateDepartmentBudget)
  e.GET("/admin/getrequistions", controllers.GetAllRequisitions)
  e.GET("/admin/requistion/:id", controllers.GetRequisitionById)
  e.PATCH("/admin/approverequistion/:id", controllers.ApproveRequistion)
  e.PATCH("/admin/rejectrequistion/:id", controllers.RejectRequistion)
  e.DELETE("/admin/deleterequistion/:id", controllers.DeleteRequistion)
  e.PATCH("/admin/approvebid/:bidId", controllers.ApproveBid)
  e.PATCH("/admin/rejectbid/:bidId", controllers.RejectBid)
  e.PATCH("/admin/approvebidmanual/:reqId", controllers.ApproveBidManually)
  e.GET("/admin/requistions/:deptId",controllers.GetRequisitionsByDepId)
e.GET("/admin/depAdmins", controllers.GetAllDeptAdmin)
  e.GET("/admin/getbids/:reqId", controllers.GetAllBids)
  e.GET("/admin/gig-requistion", controllers.GetAllGigRequisitions)
  e.PATCH("/admin/approve-gig-requistion/:id", controllers.ApproveGigRequistion)
  e.PATCH("/admin/reject-gig-requistion/:id", controllers.RejectGigRequistion)

}