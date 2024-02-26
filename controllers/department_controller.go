package controllers

import (
	"net/http"

	"procrument-system/models"
	"procrument-system/models/dtos"
	"procrument-system/responses"
	"procrument-system/services"
	"time"

	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/bson"

	"golang.org/x/net/context"
)

func CreateRequistion(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var requisition dtos.CreateRequistionDto
	var department models.Department
	if err := c.Bind(&requisition); err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Status: http.StatusBadRequest, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	if validationErr := validate.Struct(&requisition); validationErr != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Status: http.StatusBadRequest, Message: "error", Data: &echo.Map{"data": validationErr.Error()}})
	}
	jwtCookie, _ := c.Cookie("jwt")
	claims, _ := services.ParseToken(jwtCookie.Value)
	var filter = bson.M{"email": claims.Email}
	err := departmentCollection.FindOne(ctx, filter).Decode(&department)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	newRequistion := models.Requistion{
		DepartmentId: department.ID,
		ItemName:     requisition.ItemName,
		Quantity:     requisition.Quantity,
		Status:       models.Pending,
		CreatedAt:    time.Now(),
	}

	result, err := requisitionCollection.InsertOne(ctx, newRequistion)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}
	return c.JSON(http.StatusCreated, responses.UserDataResponse{Status: http.StatusCreated, Message: "success", Data: &echo.Map{"data": result}})

}
