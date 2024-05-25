package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type RequistionStatus string

const (
	Approved RequistionStatus = "approved"
	Denied   RequistionStatus = "denied"
	Pending  RequistionStatus = "pending"
)

type Requistion struct {
	ID primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	DepartmentName     string             `bson:"departmentName" json:"departmentName"`
	DepartmentId primitive.ObjectID `bson:"departmentId" json:"departmentId"`
	Description string `bson:"description" json:"description"`
	ItemName     string             `bson:"itemName" json:"itemName"`
	Price     float64             `bson:"price" json:"price"`
	Quantity     int                `bson:"quantity" json:"quantity"`
	Status       RequistionStatus   `bson:"status" json:"status"`
	CreatedAt    time.Time          `bson:"createdAt" json:"createdAt"`
	EndDate    time.Time          `bson:"endDate" json:"endDate"`
	
}
