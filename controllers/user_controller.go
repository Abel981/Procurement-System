package controllers

import (
	"net/http"
	"procrument-system/configs"
	"procrument-system/models"
	"procrument-system/models/dtos"
	"procrument-system/responses"
	"procrument-system/services"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
)

type Role string

const (
	MainAdmin       Role = "main admin"
	DepartmentAdmin Role = "department admin"
	User            Role = "user"
)

type JwtCustomClaims struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      Role   `json:"role"`
}

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

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"message": "Internal server error! please try again",
		})
	}

	newUser := models.User{

		Email:          user.Email,
		FirstName:      user.FirstName,
		LastName:       user.LastName,
		Role: "user",
		HashedPassword: string(hashedPassword),
	}

	result, err := userCollection.InsertOne(ctx, newUser)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	return c.JSON(http.StatusCreated, responses.UserDataResponse{Status: http.StatusCreated, Message: "success", Data: &echo.Map{"data": result}})
}

func GetAUser(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
jwtCookie, err := c.Cookie("jwt")
if err != nil {
	return c.JSON(http.StatusUnauthorized, responses.UserDataResponse{Status: http.StatusUnauthorized, Message: "unautorized", Data: &echo.Map{"error": err.Error()}})
}
	userId := c.Param("id")
	objId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Status: http.StatusBadRequest, Message: "invalid ObjectID", Data: &echo.Map{"error": err.Error()}})
	}
	err = services.VerifyToken(jwtCookie.Value)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, responses.UserDataResponse{Status: http.StatusUnauthorized, Message: "unautorized", Data: &echo.Map{"error": err.Error()}})

	}

	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusNotFound, responses.UserDataResponse{Status: http.StatusNotFound, Message: "user not found", Data: nil})
		}
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"error": err.Error()}})
	}

	return c.JSON(http.StatusOK, responses.UserDataResponse{Status: http.StatusOK, Message: "success", Data: &echo.Map{"user": user}})
}

func Login(c echo.Context) error {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	email := c.FormValue("email")
	password := c.FormValue("password")

	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusUnauthorized, responses.UserDataResponse{Status: http.StatusUnauthorized, Message: "Incorrect email or password", Data: nil})
		}
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"error": err.Error()}})
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password))
	if err != nil {

		return c.JSON(http.StatusUnauthorized, map[string]interface{}{
			"message": "Incorrect email or password",
		})
	}
	claims := services.JwtCustomClaims{
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      services.Role(user.Role),
	}
	tokenString, err := services.CreateToken(claims)

	if err != nil {

		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"error": err.Error()}})
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
