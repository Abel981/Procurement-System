package controllers

import (
	"net/http"

	"procrument-system/models"
	"procrument-system/models/dtos"
	"procrument-system/responses"
	"procrument-system/services"
	"time"

	"fmt"

	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
)

func LoginDepartment(c echo.Context) error {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	email := c.FormValue("email")
	password := c.FormValue("password")

	var departmentAdmin models.DepartmentAdmin
	err := departmentAdminCollection.FindOne(ctx, bson.M{"user.email": email}).Decode(&departmentAdmin)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusUnauthorized, responses.UserDataResponse{Message: "Incorrect email or password", Data: nil})
		}
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{ Message: "error", Data: &map[string]interface{}{"error": err.Error()}})
	}
	fmt.Println(departmentAdmin.DepartmentId)

	err = bcrypt.CompareHashAndPassword([]byte(departmentAdmin.HashedPassword), []byte(password))
	if err != nil {

		return c.JSON(http.StatusUnauthorized, map[string]interface{}{
			"message": "Incorrect email or password",
		})
	}
	claims := services.JwtCustomClaims{
		Id: departmentAdmin.ID,
		Email:     departmentAdmin.Email,
		FirstName: departmentAdmin.FirstName,
		LastName:  departmentAdmin.LastName,
		Role:      services.Role(departmentAdmin.Role),
	}
	tokenString, err := services.CreateToken(claims)

	if err != nil {

		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{ Message: "error", Data: &map[string]interface{}{"error": err.Error()}})
	}
	// token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// t, err := token.SignedString([]byte("secret"))

	cookie := &http.Cookie{
		Name:     "jwt",
		Value:    tokenString,
		Expires:  time.Now().Add(24 * time.Hour), // Token expires in 24 hours
		HttpOnly: true,
		Secure:   false, // Set to true in production (requires HTTPS)
		Path:     "/",
	}
	// c.Set("user",token)
	c.SetCookie(cookie)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Login successful",
	})
}

func CreateRequistion(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var requisition dtos.CreateRequistionDto
	var departmentAdmin models.DepartmentAdmin
	var department models.Department
	if err := c.Bind(&requisition); err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}

	if validationErr := validate.Struct(&requisition); validationErr != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": validationErr.Error()}})
	}
	jwtCookie, _ := c.Cookie("jwt")
	claims, _ := services.ParseToken(jwtCookie.Value)
	var filter = bson.M{"user.email": claims.Email}
	err := departmentAdminCollection.FindOne(ctx, filter).Decode(&departmentAdmin)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{ Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	filter = bson.M{"_id": departmentAdmin.DepartmentId}
	err = departmentCollection.FindOne(ctx,filter).Decode(&department)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{ Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}

	newRequistion := models.Requistion{
		DepartmentName: department.DepartmentName,
		DepartmentId: departmentAdmin.DepartmentId,

		ItemName:     requisition.ItemName,
		Quantity:     requisition.Quantity,
		Description: requisition.Description,
		Price: requisition.Price,
		Status:       models.Pending,
		CreatedAt:    time.Now(),
	}

	result, err := requisitionCollection.InsertOne(ctx, newRequistion)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{ Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	return c.JSON(http.StatusCreated, responses.UserDataResponse{ Message: "success", Data: &map[string]interface{}{"data": result}})

}

func GetDepartmentRequistions(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var requisitions []models.Requistion
	departmentId := c.Param("deptId")
	objId, err := primitive.ObjectIDFromHex(departmentId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
	}
	var filter = bson.M{"departmentId": objId}
	cursor, err := requisitionCollection.Find(ctx, filter)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}

	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var requisition models.Requistion
		if err := cursor.Decode(&requisition); err != nil {
			return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
		}

		requisitions = append(requisitions, requisition)
	}
	if len(requisitions) == 0 {

		return c.JSON(http.StatusOK, []models.Requistion{})
	}

	return c.JSON(http.StatusOK, requisitions)
}
