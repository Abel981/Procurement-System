package controllers

import (
	"fmt"
	"net/http"
	"procrument-system/configs"
	"procrument-system/models"
	"procrument-system/models/dtos"
	"procrument-system/responses"
	"procrument-system/services"
	"procrument-system/utils"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"

	"github.com/cloudinary/cloudinary-go/v2"

	"github.com/cloudinary/cloudinary-go/v2/api/uploader"
)

var userCollection *mongo.Collection = configs.GetCollection(configs.DB, "users")
var bidCollection *mongo.Collection = configs.GetCollection(configs.DB, "bids")
var verificationCollection *mongo.Collection = configs.GetCollection(configs.DB, "verification")
var bookmarkCollection *mongo.Collection = configs.GetCollection(configs.DB, "bookmarks")
var gigCollection *mongo.Collection = configs.GetCollection(configs.DB, "gigs")

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
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
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
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": validationErr.Error()}})
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
		Location: user.Country,
		Role:           "user",
		HashedPassword: string(hashedPassword),
	}

	result, err := userCollection.InsertOne(ctx, newUser)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}

	return c.JSON(http.StatusCreated, responses.UserDataResponse{Message: "success", Data: &map[string]interface{}{"data": result}})
}

func GetAUser(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userId := c.Param("id")
	objId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
	}

	var user models.User
	err = userCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusNotFound, responses.UserDataResponse{Message: "user not found", Data: nil})
		}
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"error": err.Error()}})
	}

	return c.JSON(http.StatusOK, user)
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
			return c.JSON(http.StatusUnauthorized, responses.UserDataResponse{Message: "Incorrect email or password", Data: nil})
		}
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"error": err.Error()}})
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password))
	if err != nil {

		return c.JSON(http.StatusUnauthorized, map[string]interface{}{
			"message": "Incorrect email or password",
		})
	}
	claims := services.JwtCustomClaims{
		Id:        user.ID.Hex(),
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      services.Role(user.Role),
	}
	tokenString, err := services.CreateToken(claims)

	if err != nil {

		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"error": err.Error()}})
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
func LogoutUser(c echo.Context) error {
	// Create a new cookie with the same name as the one you want to delete
	cookie := new(http.Cookie)
	cookie.Name = "jwt"
	// Set the cookie's expiration date in the past to delete it
	cookie.Expires = time.Unix(0, 0)
	// Set the path of the cookie to match the one you want to delete
	cookie.Path = "/"
	// Set the HTTP-only flag to true if the cookie is HTTP-only
	cookie.HttpOnly = true

	// Set the cookie in the response header to delete it
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Logged out",
	})
}

func CreateBid(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var bid dtos.BidDto
	// var user models.User
	var requisition models.Requistion
	defer cancel()
	file, err := c.FormFile("imageFile")
	if err != nil {
		return err
	}

	// Open uploaded file
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	// requisitionId := c.Param("reqId")
	// objectID, err := primitive.ObjectIDFromHex(requisitionId)
	// if err != nil {
	// 	// If parsing fails, return a Bad Request response
	// 	return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid departmentID"})
	// }

	if err := c.Bind(&bid); err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	fmt.Println("hey 1")
	objectID, err := primitive.ObjectIDFromHex(bid.RequistionId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "Incorrect email or password", Data: nil})

	}
	fmt.Println("hey 2")
	err = requisitionCollection.FindOne(ctx, bson.M{"_id": objectID}).Decode(&requisition)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "Incorrect email or password", Data: nil})
		}
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"error": err.Error()}})
	}
	fmt.Println("hey 3")

	//todo add required tag in bid dto
	if validationErr := validate.Struct(&bid); validationErr != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": validationErr.Error()}})
	}
	fmt.Println("hey 4")
	var credentials = configs.EnvCloudinaryCredentials()
	cld, _ := cloudinary.NewFromParams(credentials.CloudName, credentials.ApiKey, credentials.ApiSecret)
	resp, err := cld.Upload.Upload(ctx, src, uploader.UploadParams{})
	if err != nil {
		fmt.Println("error uploading")
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"error": err.Error()}})
	}

	jwtCookie, _ := c.Cookie("jwt")
	claims, _ := services.ParseToken(jwtCookie.Value)
	supplierObjectId, _ := primitive.ObjectIDFromHex(claims.Id)
	fmt.Println(claims.Id)
	fmt.Println("hey 5")

	// var filter = bson.M{"email": claims.Email}
	// err = userCollection.FindOne(ctx, filter).Decode(&user)
	// if err != nil {
	// 	return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	// }
	// supplierID, _ := primitive.ObjectIDFromHex(claims.ID)
	newBid := models.Bid{
		SupplierId:   supplierObjectId,
		RequistionId: objectID,
		Price:        bid.Price,
		Status:       models.Pending,
		CreatedAt:    time.Now(),
		DocumentUrl:  resp.SecureURL,
	}
	result, err := bidCollection.InsertOne(ctx, newBid)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	fmt.Println("hey 6")
	return c.JSON(http.StatusCreated, responses.UserDataResponse{Message: "success", Data: &map[string]interface{}{"data": result}})

}
func CreateBookmark(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	requisitionId := c.Param("reqId")
	reqId, err := primitive.ObjectIDFromHex(requisitionId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
	}
	jwtCookie, _ := c.Cookie("jwt")
	claims, _ := services.ParseToken(jwtCookie.Value)
	supplierObjectId, _ := primitive.ObjectIDFromHex(claims.Id)

	newBookmark := models.Bookmark{
		SupplierId:   supplierObjectId,
		RequistionId: reqId,
		CreatedAt:    time.Now(),
	}

	_, err = bookmarkCollection.InsertOne(ctx, newBookmark)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "bookmark created",
	})
}
func GetBookmarks(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var bookmarks []models.Bookmark

	jwtCookie, _ := c.Cookie("jwt")
	claims, _ := services.ParseToken(jwtCookie.Value)
	supplierObjectId, _ := primitive.ObjectIDFromHex(claims.Id)
	cursor, err := bookmarkCollection.Find(ctx, bson.M{"supplierId": supplierObjectId})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var bk models.Bookmark
		if err := cursor.Decode(&bk); err != nil {
			return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
		}

		bookmarks = append(bookmarks, bk)
	}

	if len(bookmarks) == 0 {
		return c.JSON(http.StatusOK, []models.Bookmark{})
	}

	return c.JSON(http.StatusOK, bookmarks)
}

func CreateGig(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var gigDto dtos.GigDto

	defer cancel()
	jwtCookie, _ := c.Cookie("jwt")
	claims, _ := services.ParseToken(jwtCookie.Value)
	supplierObjectId, _ := primitive.ObjectIDFromHex(claims.Id)
	if err := c.Bind(&gigDto); err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	err := c.Request().ParseMultipartForm(32 << 20) // 32 MB limit
	if err != nil {
		return err
	}

	files := c.Request().MultipartForm.File["images"]
	var imageUrls []string
	var credentials = configs.EnvCloudinaryCredentials()
	// Iterate over each file
	for _, fileHeader := range files {
		// Open uploaded file
		file, err := fileHeader.Open()
		if err != nil {
			return err
		}
		defer file.Close()

		// Upload file to Cloudinary
		cld, _ := cloudinary.NewFromParams(credentials.CloudName, credentials.ApiKey, credentials.ApiSecret)
		resp, err := cld.Upload.Upload(ctx, file, uploader.UploadParams{})
		if err != nil {
			fmt.Println("error uploading")
			return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"error": err.Error()}})
		}

		// Append the URL of the uploaded image to imageUrls
		imageUrls = append(imageUrls, resp.SecureURL)
	}

	newGig := models.Gig{
		SupplierId:  supplierObjectId,
		Title:       gigDto.Title,
		Description: gigDto.Description,
		Price:       gigDto.Price,
		ImagesUrl:   imageUrls,
		CreatedAt:   time.Now(),
	}
	_, err = gigCollection.InsertOne(ctx, newGig)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "gig created",
	})
}
func GetSupplierGigs(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var gigs []models.Gig
	jwtCookie, _ := c.Cookie("jwt")
	claims, _ := services.ParseToken(jwtCookie.Value)
	supplierObjectId, _ := primitive.ObjectIDFromHex(claims.Id)
	cursor, err := gigCollection.Find(ctx, bson.M{"supplierId": supplierObjectId})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var gig models.Gig
		if err := cursor.Decode(&gig); err != nil {
			return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
		}

		gigs = append(gigs, gig)
	}
	if len(gigs) == 0 {
		return c.JSON(http.StatusOK, []models.Gig{})
	}

	return c.JSON(http.StatusOK, gigs)
}

func GetRequisitionById(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	requisitionId := c.Param("id")
	fmt.Println(requisitionId)
	objId, err := primitive.ObjectIDFromHex(requisitionId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
	}
	fmt.Println("hey 2")

	var requisition models.Requistion
	err = requisitionCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&requisition)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusNotFound, responses.UserDataResponse{Message: "user not found", Data: nil})
		}
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"error": err.Error()}})
	}

	return c.JSON(http.StatusOK, requisition)
}

func GetPasswordResetCode(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	email := c.FormValue("email")

	var user models.User
	err := userCollection.FindOne(ctx, bson.M{"email": email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusUnauthorized, responses.UserDataResponse{Message: "Incorrect email or password", Data: nil})
		}
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"error": err.Error()}})
	}

	code := utils.GenerateRandomString(10)

	services.SendEmail(services.EmailRecipientData{
		Id:                user.ID.Hex(),
		FirstName:         user.FirstName,
		LastName:          user.LastName,
		Email:             user.Email,
		ResetPasswordText: code,
	}, "./templates/reset_password.html")
	verificationData := &models.VerificationData{

		Email:     user.Email,
		Code:      code,
		Type:      "reset_password",
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}

	_, err = verificationCollection.InsertOne(ctx, verificationData)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"data": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message": "Please check your mail for password reset code",
	})
}

func VerifyPasswordReset(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var resetPasswordBody dtos.ResetPasswordVerificationDto
	var verificationData models.VerificationData

	if err := c.Bind(&resetPasswordBody); err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}

	var filter = bson.M{"code": resetPasswordBody.Code, "type": "reset_password"}
	_ = verificationCollection.FindOne(ctx, filter).Decode(&verificationData)

	if resetPasswordBody.Code != verificationData.Code || resetPasswordBody.Type != verificationData.Type {
		return c.JSON(http.StatusNotAcceptable, map[string]interface{}{
			"message": "The request is not acceptable",
		})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"resetCode": verificationData.Code,
	})
}

func ResetPassword(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	userId := c.Param("id")
	secretCode := c.Param("secret")
	objId, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
	}
	var user models.User
	var resetPasswordBody dtos.ResetPasswordDto
	var verificationData models.VerificationData
	if err := c.Bind(&resetPasswordBody); err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	fmt.Println("hey 1")
	err = userCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusUnauthorized, responses.UserDataResponse{Message: "Incorrect email or password", Data: nil})
		}
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"error": err.Error()}})
	}
	err = verificationCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&verificationData)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"data": err.Error()})
	}

	if verificationData.Code != secretCode {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"error": "internal sserver error"}})

	}

	if resetPasswordBody.Password != resetPasswordBody.ConfirmPassword {
		return c.JSON(http.StatusNotAcceptable, map[string]interface{}{
			"message": "Password and re-entered Password are not same",
		})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(resetPasswordBody.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"message": "Internal server error! please try again",
		})
	}

	filter := bson.M{"_id": objId}
	update := bson.M{"$set": bson.M{"hashedpassword": string(hashedPassword)}}

	_, err = userCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}

	_, err = verificationCollection.DeleteOne(ctx, bson.M{"email": verificationData.Email, "type": "reset_password"})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	return c.JSON(http.StatusOK, "password reset successfully")
}
