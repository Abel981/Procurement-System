package dtos

import (
	"go.mongodb.org/mongo-driver/bson/primitive"

	"procrument-system/models"
)

type CreateRequistionDto struct {
	DepartmentId primitive.ObjectID      `bson:"departmentId"`
	ItemName     string                  `bson:"itemName"`
	Quantity     int                     `bson:"quantity"`
	Status       models.RequistionStatus `bson:"status"`
}
