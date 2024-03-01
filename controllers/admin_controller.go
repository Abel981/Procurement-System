package controllers

import (
	"log"
	"net/http"
	"procrument-system/configs"
	"procrument-system/models"
	"procrument-system/models/dtos"
	"procrument-system/responses"
	"procrument-system/services"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
)

var adminCollection *mongo.Collection = configs.GetCollection(configs.DB, "admin")
var departmentCollection *mongo.Collection = configs.GetCollection(configs.DB, "departments")
var departmentAdminCollection *mongo.Collection = configs.GetCollection(configs.DB, "departmentAdmin")
var requisitionCollection *mongo.Collection = configs.GetCollection(configs.DB, "requisition")

// var validate = validator.New()

func CreateAdmin(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var user dtos.UserSignupDTO
	defer cancel()
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
		Role:           "admin",
		HashedPassword: string(hashedPassword),
	}

	result, err := adminCollection.InsertOne(ctx, newUser)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	return c.JSON(http.StatusCreated, responses.UserDataResponse{Status: http.StatusCreated, Message: "success", Data: &echo.Map{"data": result}})
}

func AdminLogin(c echo.Context) error {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	email := c.FormValue("email")
	password := c.FormValue("password")

	var admin models.Admin

	err := adminCollection.FindOne(ctx, bson.M{"email": email}).Decode(&admin)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusUnauthorized, responses.UserDataResponse{Status: http.StatusUnauthorized, Message: "Incorrect email or password", Data: nil})
		}
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"error": err.Error()}})
	}
	err = bcrypt.CompareHashAndPassword([]byte(admin.HashedPassword), []byte(password))
	if err != nil {

		return c.JSON(http.StatusUnauthorized, map[string]interface{}{
			"message": "Incorrect email or password",
		})
	}
	claims := services.JwtCustomClaims{
		FirstName: admin.FirstName,
		LastName:  admin.LastName,
		Role:      services.Role(admin.Role),
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

func AddDepartment(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var department dtos.AddDepartmentDto
	defer cancel()
	if err := c.Bind(&department); err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Status: http.StatusBadRequest, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}
	result, err := departmentCollection.InsertOne(ctx, department)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}
	return c.JSON(http.StatusCreated, result)

}

func CreateDepartmentAdmin(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	departmentId := c.Param("id")
	objId, err := primitive.ObjectIDFromHex(departmentId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Status: http.StatusBadRequest, Message: "invalid ObjectID", Data: &echo.Map{"error": err.Error()}})
	}
	var departmentAdmin dtos.UserSignupDTO

	if err := c.Bind(&departmentAdmin); err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Status: http.StatusBadRequest, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(departmentAdmin.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"message": "Internal server error! please try again",
		})
	}

	newDepartmentAdmin :=
		models.DepartmentAdmin{
			DepartmentId: objId,
			User: models.User{

				Email:          departmentAdmin.Email,
				FirstName:      departmentAdmin.FirstName,
				LastName:       departmentAdmin.LastName,
				Role:           models.Role(services.DepartmentAdmin),
				HashedPassword: string(hashedPassword),
			},
		}
	filter := bson.M{"_id": objId}
	// update := bson.M{"$set": bson.M{"departmentAdmin": newDepartmentAdmin}}
	result, err := departmentAdminCollection.InsertOne(ctx, newDepartmentAdmin)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}
	_, err = departmentCollection.UpdateOne(ctx, filter, bson.M{"$set": bson.M{"departmentAdminId": result.InsertedID}})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}
	return c.JSON(http.StatusOK, "success")

}

func GetAllRequisitions(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var requistion []models.Requistion
	requisitionStatus := c.QueryParam("status")
	var filter bson.M
	if requisitionStatus != "" {
		filter = bson.M{"status": requisitionStatus}
	}
	cursor, err := requisitionCollection.Find(ctx, filter)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var req models.Requistion
		if err := cursor.Decode(&req); err != nil {
			return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
		}

		requistion = append(requistion, req)
	}
	if len(requistion) == 0 {

		return c.JSON(http.StatusOK, []models.Requistion{})
	}

	return c.JSON(http.StatusOK, requistion)
}

func ChangeRequistionStatus(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	requistionId := c.Param("id")
	objId, err := primitive.ObjectIDFromHex(requistionId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Status: http.StatusBadRequest, Message: "invalid ObjectID", Data: &echo.Map{"error": err.Error()}})
	}
	var requistionStatus struct {
		Status string `json:"status"`
	}

	if err := c.Bind(&requistionStatus); err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Status: http.StatusBadRequest, Message: "error", Data: &echo.Map{"data": err.Error()}})

	}
	filter := bson.M{"_id": objId}
	update := bson.M{"$set": bson.M{"status": requistionStatus.Status}}

	_, err = requisitionCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}
	return c.JSON(http.StatusOK, "success")

}

func ApproveBid(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	bidId := c.Param("bidId")
	objId, err := primitive.ObjectIDFromHex(bidId)

	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Status: http.StatusBadRequest, Message: "invalid ObjectID", Data: &echo.Map{"error": err.Error()}})
	}
	var updatedBid models.Bid
	updateResult, err := bidCollection.UpdateOne(ctx,
		bson.M{"_id": objId},
		bson.M{"$set": bson.M{"status": models.Approved}},
	)

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if updateResult.ModifiedCount == 0 {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Bid not found or already accepted"})
	}
	err = bidCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&updatedBid)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch updated bid"})
	}
	var wg sync.WaitGroup

	// Start goroutine to send email to approved bid
	wg.Add(1)
	go func() {
		defer wg.Done()
		// var approvedSupplier models.User
		// err = userCollection.FindOne(ctx, bson.M{"_id": updatedBid.SupplierId}).Decode(&approvedSupplier)
		services.SendEmail(services.EmailRecipientData{
			FirstName: "abel",
			LastName:  "wen",
			Email:     "abel.wen07@gmail.com",
		}, "./templates/accepted_bid.html")
	}()

	// Start goroutines to update status and send emails to rejected bids
	cursor, err := bidCollection.Find(ctx, bson.M{"_id": bson.M{"$ne": objId}, "requistionId": bson.M{"$eq": updatedBid.RequistionId}})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	defer cursor.Close(ctx)

	var rejectedSupplier models.User

	for cursor.Next(ctx) {
		var rejectedBid models.Bid
		if err := cursor.Decode(&rejectedBid); err != nil {
			log.Println(err)
			continue
		}
		err = userCollection.FindOne(ctx, bson.M{"_id": rejectedBid.SupplierId}).Decode(&rejectedSupplier)


		// Update status of rejected bid
		wg.Add(1)
		go func(id primitive.ObjectID) {
			defer wg.Done()
			_, err := bidCollection.UpdateOne(ctx,
				bson.M{"_id": id},
				bson.M{"$set": bson.M{"status": models.Denied}},
			)
			if err != nil {
				log.Printf("Error updating status of bid %s: %v\n", id.Hex(), err)
			}
		}(rejectedBid.ID)

		// Send email to rejected bid
		wg.Add(1)
		go func() {
			defer wg.Done()
		services.SendEmail(services.EmailRecipientData{
			FirstName: rejectedSupplier.FirstName,
			LastName:  rejectedSupplier.LastName,
			Email:     rejectedSupplier.Email,
		}, "./templates/rejected_bid.html")
		}()
	}

	wg.Wait()

	return c.JSON(http.StatusOK, map[string]string{"message": "Bid accepted successfully"})
}

// func ApproveBid(c echo.Context) error {
// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 	defer cancel()
// 	bidId := c.Param("bidId")
// 	objId, err := primitive.ObjectIDFromHex(bidId)

// 	if err != nil {
// 		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Status: http.StatusBadRequest, Message: "invalid ObjectID", Data: &echo.Map{"error": err.Error()}})
// 	}
// 	var updatedBid models.Bid
// 	updateResult, err := bidCollection.UpdateOne(ctx,
// 		bson.M{"_id": objId},
// 		bson.M{"$set": bson.M{"status": models.Approved}},
// 	)

// 	if err != nil {
// 		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
// 	}
// 	if updateResult.ModifiedCount == 0 {
// 		return c.JSON(http.StatusNotFound, map[string]string{"error": "Bid not found or already accepted"})
// 	}
// 	err = bidCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&updatedBid)
// 	if err != nil {
// 		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch updated bid"})
// 	}
// 	_, err = bidCollection.UpdateMany(ctx,
// 		bson.M{"_id": bson.M{"$ne": objId}, "requistionId": bson.M{"$eq": updatedBid.RequistionId}},
// 		bson.M{"$set": bson.M{"status": models.Denied}},
// 	)
// 	if err != nil {
// 		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
// 	}
// 	return c.JSON(http.StatusOK, map[string]string{"message": "Bid accepted successfully"})
// }

func GetAllBids(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var bids []models.Bid
	requisitionId := c.Param("reqId")
	objId, err := primitive.ObjectIDFromHex(requisitionId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Status: http.StatusBadRequest, Message: "invalid ObjectID", Data: &echo.Map{"error": err.Error()}})
	}
	var filter = bson.M{"requistionId": objId}
	cursor, err := bidCollection.Find(ctx, filter)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
	}

	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var bid models.Bid
		if err := cursor.Decode(&bid); err != nil {
			return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Status: http.StatusInternalServerError, Message: "error", Data: &echo.Map{"data": err.Error()}})
		}

		bids = append(bids, bid)
	}
	if len(bids) == 0 {

		return c.JSON(http.StatusOK, []models.Requistion{})
	}

	return c.JSON(http.StatusOK, bids)
}
