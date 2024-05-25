package controllers

import (
	"fmt"
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

func checkDepartmentExistence(ctx context.Context, name string) (bool, error) {

	result := departmentCollection.FindOne(ctx, bson.M{"departmentname": name})

	if result.Err() != nil {
		if result.Err() == mongo.ErrNoDocuments {
			return false, nil
		}
		return false, result.Err()
	}

	return true, nil
}

// CreateAdmin creates a new admin user.
//
//	@Summary		Create a new admin user
//	@Description	Create a new admin user with the provided details
//	@Tags			admin
//	@Accept			json
//	@Produce		json
//	@Param			adminData	formData	dtos.UserSignupDTO	true	"j"
//	@Router			/admin/signup [post]
func CreateAdmin(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var user dtos.UserSignupDTO
	defer cancel()
	if err := c.Bind(&user); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"data": err.Error()})
	}

	//use the validator library to validate required fields
	if validationErr := validate.Struct(&user); validationErr != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{"data": validationErr.Error()})
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
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{"data": err.Error()})
	}

	return c.JSON(http.StatusCreated, map[string]interface{}{"id": result.InsertedID})
}

// AdminLogin handles the authentication of admin users.
// @Summary Admin login
// @Description Authenticate an admin user using email and password
// @Tags admin
// @Accept  json
// @Produce  json
// @Param email formData string true "Email address"
// @Param password formData string true "Password"
// @Success 200 {object} map[string]interface{} "Login successful"
// @Failure 401 {object} responses.UserDataResponse "Unauthorized: Incorrect email or password"
// @Failure 500 {object} responses.UserDataResponse "Internal server error"
// @Router /admin/login [post]


func AdminLogin(c echo.Context) error {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	email := c.FormValue("email")
	password := c.FormValue("password")

	var admin models.Admin

	err := adminCollection.FindOne(ctx, bson.M{"email": email}).Decode(&admin)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusUnauthorized, responses.UserDataResponse{Message: "Incorrect email or password", Data: nil})
		}
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"error": err.Error()}})
	}
	err = bcrypt.CompareHashAndPassword([]byte(admin.HashedPassword), []byte(password))
	if err != nil {

		return c.JSON(http.StatusUnauthorized, map[string]interface{}{
			"message": "Incorrect email or password",
		})
	}
	fmt.Println(admin.ID)
	claims := services.JwtCustomClaims{
		Id:        admin.ID.Hex(),
		FirstName: admin.FirstName,
		LastName:  admin.LastName,
		Role:      services.Role(admin.Role),
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

func AdminLogout(c echo.Context) error {
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

func AddDepartment(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	var department dtos.AddDepartmentDto
	defer cancel()

	if err := c.Bind(&department); err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	isFound, err := checkDepartmentExistence(ctx,department.DepartmentName)
	if err!= nil {
        return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
    }

	if isFound {
        return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"message": "Department Already Exists!",
		})
    }
	result, err := departmentCollection.InsertOne(ctx, department)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	return c.JSON(http.StatusCreated, result)

}

func GetAllDepartments(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var department []models.Department

	var filter bson.M

	cursor, err := departmentCollection.Find(ctx, filter)

	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}

	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var dep models.Department
		if err := cursor.Decode(&dep); err != nil {
			return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
		}

		department = append(department, dep)
	}
	if len(department) == 0 {

		return c.JSON(http.StatusOK, []models.Requistion{})
	}

	return c.JSON(http.StatusOK, department)
}
func GetDepartmentById(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	departmentId := c.Param("id")

	objId, err := primitive.ObjectIDFromHex(departmentId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
	}


	var department models.Department
	err = departmentCollection.FindOne(ctx, bson.M{"_id": objId}).Decode(&department)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.JSON(http.StatusNotFound, responses.UserDataResponse{Message: "user not found", Data: nil})
		}
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"error": err.Error()}})
	}

	return c.JSON(http.StatusOK, department)
}

func UpdateDepartmentBudget(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	departmentId := c.Param("id")
	objId, err := primitive.ObjectIDFromHex(departmentId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
	}
	var departmentBudget struct {
		DepartmentBudget float64 `json:"departmentBudget"`
	}

	if err := c.Bind(&departmentBudget); err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})

	}
	filter := bson.M{"_id": objId}
	update := bson.M{"$set": bson.M{"departmentbudget": departmentBudget.DepartmentBudget}}

	_, err = departmentCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	return c.JSON(http.StatusOK, "success")

}

func CreateDepartmentAdmin(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	departmentId := c.Param("id")
	objId, err := primitive.ObjectIDFromHex(departmentId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
	}
	var departmentAdmin dtos.UserSignupDTO

	if err := c.Bind(&departmentAdmin); err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
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

			Email:          departmentAdmin.Email,
			FirstName:      departmentAdmin.FirstName,
			LastName:       departmentAdmin.LastName,
			Role:           models.Role(services.DepartmentAdmin),
			HashedPassword: string(hashedPassword),
		}
	filter := bson.M{"_id": objId}
	// update := bson.M{"$set": bson.M{"departmentAdmin": newDepartmentAdmin}}
	result, err := departmentAdminCollection.InsertOne(ctx, newDepartmentAdmin)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	_, err = departmentCollection.UpdateOne(ctx, filter, bson.M{"$set": bson.M{"departmentAdminId": result.InsertedID}})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	return c.JSON(http.StatusOK, "success")

}
func GetAllDeptAdmin(c echo.Context) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    var deptAdmin []models.DepartmentAdmin
 
    filter := bson.M{} // Initialize the filter map here



    cursor, err := departmentAdminCollection.Find(ctx, filter)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
    }

    defer cursor.Close(ctx)
    
    for cursor.Next(ctx) {
        var dAdmin models.DepartmentAdmin
        if err := cursor.Decode(&dAdmin); err != nil {
            return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
        }

        deptAdmin = append(deptAdmin, dAdmin)
    }

    if len(deptAdmin) == 0 {
        return c.JSON(http.StatusOK, []models.Requistion{})
    }

    return c.JSON(http.StatusOK, deptAdmin)
}
func DeleteDepartmentAdmin(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	departmentId := c.Param("id")
	objId, err := primitive.ObjectIDFromHex(departmentId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "Invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
	}

	// Define the filter to delete the department admin
	filter := bson.M{"_id": objId}
	_, err = departmentAdminCollection.DeleteOne(ctx, filter)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "Error", Data: &map[string]interface{}{"data": err.Error()}})
	}

	// Remove departmentAdminId field from the department collection
	_, err = departmentCollection.UpdateOne(ctx, bson.M{"departmentAdminId": objId}, bson.M{"$unset": bson.M{"departmentAdminId": ""}})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "Error updating department", Data: &map[string]interface{}{"error": err.Error()}})
	}

	return c.JSON(http.StatusOK, "Success")
}

func GetRequisitionsByDepId(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
var requisition []models.Requistion
	departmentId := c.Param("deptId")
	
	objId, err := primitive.ObjectIDFromHex(departmentId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
	}

	cursor, err := requisitionCollection.Find(ctx , bson.M{"departmentId": objId,"status": "approved"})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var req models.Requistion
		if err := cursor.Decode(&req); err != nil {
			return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
		}

		requisition = append(requisition, req)
	}
	if len(requisition) == 0 {

		return c.JSON(http.StatusOK, []models.Requistion{})
	}
	
	return c.JSON(http.StatusOK, requisition)

	
}

func GetAllRequisitions(c echo.Context) error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    var requistion []models.Requistion
    itemName := c.QueryParam("itemName")
    requisitionStatus := c.QueryParam("status")
    filter := bson.M{} // Initialize the filter map here

    if requisitionStatus != "" {
        filter["status"] = requisitionStatus
    }

    if itemName != "" {
        regexPattern := bson.M{"$regex": itemName, "$options": "i"}
        filter["itemName"] = regexPattern
    }

    cursor, err := requisitionCollection.Find(ctx, filter)
    if err != nil {
        return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
    }

    defer cursor.Close(ctx)
    
    for cursor.Next(ctx) {
        var req models.Requistion
        if err := cursor.Decode(&req); err != nil {
            return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
        }

        requistion = append(requistion, req)
    }

    if len(requistion) == 0 {
        return c.JSON(http.StatusOK, []models.Requistion{})
    }

    return c.JSON(http.StatusOK, requistion)
}


func ApproveRequistion(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
var approveReqDto dtos.ApproveReqDto 
if err := c.Bind(&approveReqDto); err != nil {
	return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
}
	requistionId := c.Param("id")
	objId, err := primitive.ObjectIDFromHex(requistionId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
	}
	// var requistionStatus struct {
	// 	Status string `json:"status"`
	// }

	// if err := c.Bind(&requistionStatus); err != nil {
	// 	return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})

	// }
	filter := bson.M{"_id": objId}
	update := bson.M{"$set": bson.M{"status": models.Approved, "endDate": approveReqDto.EndDate}}

	updatedResult, err := requisitionCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	var updatedDocument models.Requistion
	if updatedResult.ModifiedCount > 0 {
        // Retrieve the updated document
        err = requisitionCollection.FindOne(ctx, filter).Decode(&updatedDocument)
        if err != nil {
            log.Fatal(err)
        }
	}
	var departmentAdmin models.DepartmentAdmin

	_= departmentAdminCollection.FindOne(ctx, bson.M{"deparementId":updatedDocument.DepartmentId}).Decode(&departmentAdmin)
	services.SendEmail(services.EmailRecipientData{
		FirstName: departmentAdmin.FirstName,
		LastName: departmentAdmin.LastName,
		Email: departmentAdmin.Email,

	}, "./templates/approved_req.html")
	return c.JSON(http.StatusOK,  map[string]interface{}{
		"message": "Requisition Approved and auction Started",
	})

}
func RejectRequistion(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	requistionId := c.Param("id")
	objId, err := primitive.ObjectIDFromHex(requistionId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
	}
	// var requistionStatus struct {
	// 	Status string `json:"status"`
	// }

	// if err := c.Bind(&requistionStatus); err != nil {
	// 	return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})

	// }
	filter := bson.M{"_id": objId}
	update := bson.M{"$set": bson.M{"status": models.Denied}}

	_, err = requisitionCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"message": "Requisition Not found",
		})
	}
	return c.JSON(http.StatusOK,  map[string]interface{}{
		"message": "Requisition Rejected",
	})

}
func DeleteRequistion(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	requistionId := c.Param("id")
	objId, err := primitive.ObjectIDFromHex(requistionId)
	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
	}
	// var requistionStatus struct {
	// 	Status string `json:"status"`
	// }

	// if err := c.Bind(&requistionStatus); err != nil {
	// 	return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})

	// }
	filter := bson.M{"_id": objId}
	

	_, err = requisitionCollection.DeleteOne(ctx, filter)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}
	return c.JSON(http.StatusOK, "success")

}

func ApproveBid(c echo.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	bidId := c.Param("bidId")
	objId, err := primitive.ObjectIDFromHex(bidId)

	if err != nil {
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
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
		_ = userCollection.FindOne(ctx, bson.M{"_id": rejectedBid.SupplierId}).Decode(&rejectedSupplier)

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
// 		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Status: http.StatusBadRequest, Message: "invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
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
		return c.JSON(http.StatusBadRequest, responses.UserDataResponse{Message: "invalid ObjectID", Data: &map[string]interface{}{"error": err.Error()}})
	}
	var filter = bson.M{"requistionId": objId}
	cursor, err := bidCollection.Find(ctx, filter)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
	}

	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var bid models.Bid
		if err := cursor.Decode(&bid); err != nil {
			return c.JSON(http.StatusInternalServerError, responses.UserDataResponse{Message: "error", Data: &map[string]interface{}{"data": err.Error()}})
		}

		bids = append(bids, bid)
	}
	if len(bids) == 0 {

		return c.JSON(http.StatusOK, []models.Requistion{})
	}

	return c.JSON(http.StatusOK, bids)
}
