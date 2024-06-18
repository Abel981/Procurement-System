package utils

import (
	"context"
	"fmt"
	"procrument-system/configs"
	"procrument-system/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var departmentCollection *mongo.Collection = configs.GetCollection(configs.DB, "departments")

func IsBudgetEnough(ctx context.Context, id primitive.ObjectID, totalPrice float32) (bool, error) {
	var department models.Department
	err := departmentCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&department)

	if err != nil {
		return false, fmt.Errorf("error finding department: %v", err)
	}
	if float32(department.DepartmentBudget) >= totalPrice {
		return true, nil
	}
	return false, nil
}
