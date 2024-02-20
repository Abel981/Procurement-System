package controllers

import (
	"net/http"
	"procrument-system/configs"
	"procrument-system/models"
	"procrument-system/models/dtos"
	"procrument-system/responses"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/net/context"
)

var userCollection *mongo.Collection = configs.GetCollection(configs.DB, "users")
var validate = validator.New()

func CreateUser(c echo.Context) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    var user dtos.UserSignupDTO
    defer cancel()

    //validate the request body
    if err := c.Bind(&user); err != nil {
        return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Status: http.StatusBadRequest, Message: "error", Data: &echo.Map{"data": err.Error()}})
    }

    //use the validator library to validate required fields
    if validationErr := validate.Struct(&user); validationErr != nil {
        return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Status: http.StatusBadRequest, Message: "error", Data: &echo.Map{"data": validationErr.Error()}})
    }

    newUser := models.User{
        Id:       primitive.NewObjectID(),
        Email:     user.Email,
        FirstName: user.FirstName,
        LastName:    user.LastName,
    }

    result, err := userCollection.InsertOne(ctx, newUser)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
    }

    return c.JSON(http.StatusCreated, responses.UserDataResponse{Status: http.StatusCreated, Message: "success", Data: &echo.Map{"data": result}})
}

func GetAUser(c echo.Context) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    userId := c.Param("id")
    var user models.User
    defer cancel()

    objId, _ := primitive.ObjectIDFromHex(userId)

    err := userCollection.FindOne(ctx, bson.M{"id": objId}).Decode(&user)

    if err != nil {
        return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
    }

    return c.JSON(http.StatusOK, responses.UserDataResponse{Status: http.StatusOK, Message: "success", Data: &echo.Map{"data": user}})
}