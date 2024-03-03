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

var userCollection *mongo.Collection = configs.GetCollection(configs.DB, "users")
var bidCollection *mongo.Collection = configs.GetCollection(configs.DB, "bids")
var validate = validator.New()

func checkUserExistence(ctx context.Context, email string) (bool, error) {

	result := userCollection.FindOne(ctx, bson.M{"email": email})

	if result.Err() != nil {
		if result.Err() == mongo.ErrNoDocuments {
			return false, nil
		}
		return false, result.Err()
	}

	return true, nil
}

func CreateUser(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var user dtos.UserSignupDTO
	defer cancel()

	//validate the request body
	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{ Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}

	isFound, err := checkUserExistence(ctx, user.Email)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"message": "Internal server error! please try again",
		})
	}
	if isFound {
		return c.JSON(http.StatusConflict, map[string]interface{}{
			"message": "User already exists",
		})
	}
	if validationErr := validate.Struct(&user); validationErr != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{ Message: "error", Data: &map[string]interface{}{"data": validationErr.Error()}})
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
		Role:           "user",
		HashedPassword: string(hashedPassword),
	}

	result, err := userCollection.InsertOne(ctx, newUser)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{ Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}

	return c.JSON(http.StatusCreated, responses.UserDataResponse{ Message: "success", Data: &map[string]interface{}{"data": result}})
}

func GetAUser(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userId := c.Param("id")
	objId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{ Message: "invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
	}

	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusNotFound, responses.UserDataResponse{Message: "user not found", Data: nil})
		}
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{ Message: "error", Data: &map[string]interface{}{"error": err.Error()}})
	}

	return c.JSON(http.StatusOK, responses.UserDataResponse{ Message: "success", Data: &map[string]interface{}{"user": user}})
}

func LoginUser(c echo.Context) error {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	email := c.FormValue("email")
	password := c.FormValue("password")

	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusUnauthorized, responses.UserDataResponse{ Message: "Incorrect email or password", Data: nil})
		}
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{ Message: "error", Data: &map[string]interface{}{"error": err.Error()}})
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password))
	if err != nil {

		return c.JSON(http.StatusUnauthorized, map[string]interface{}{
			"message": "Incorrect email or password",
		})
	}
	claims := services.JwtCustomClaims{
		Id:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      services.Role(user.Role),
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

func CreateBid(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var bid dtos.BidDto
	// var user models.User
	var requisition models.Requistion
	defer cancel()
	// requisitionId := c.Param("reqId")
	// objectID, err := primitive.ObjectIDFromHex(requisitionId)
	// if err != nil {
	// 	// If parsing fails, return a Bad Request response
	// 	return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid departmentID"})
	// }

	if err := c.Bind(&bid); err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{ Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	objectID, err := primitive.ObjectIDFromHex(bid.RequistionId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{ Message: "Incorrect email or password", Data: nil})

	}
	err = requisitionCollection.FindOne(ctx, bson.M{"_id": objectID}).Decode(&requisition)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "Incorrect email or password", Data: nil})
		}
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{ Message: "error", Data: &map[string]interface{}{"error": err.Error()}})
	}

	//todo add required tag in bid dto
	if validationErr := validate.Struct(&bid); validationErr != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{ Message: "error", Data: &map[string]interface{}{"data": validationErr.Error()}})
	}

	jwtCookie, _ := c.Cookie("jwt")
	claims, _ := services.ParseToken(jwtCookie.Value)
	// var filter = bson.M{"email": claims.Email}
	// err = userCollection.FindOne(ctx, filter).Decode(&user)
	// if err != nil {
	// 	return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	// }
	// supplierID, _ := primitive.ObjectIDFromHex(claims.ID)
	newBid := models.Bid{
		SupplierId:   claims.Id,
		RequistionId: objectID,
		Price:        bid.Price,
		Status:       models.Pending,
		CreatedAt:    time.Now(),
	}
	result, err := bidCollection.InsertOne(ctx, newBid)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{ Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	return c.JSON(http.StatusCreated, responses.UserDataResponse{ Message: "success", Data: &map[string]interface{}{"data": result}})

}
