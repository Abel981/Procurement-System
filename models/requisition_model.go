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

	DepartmentId primitive.ObjectID `bson:"departmentId" json:"departmentId"`
	ItemName     string             `bson:"itemName" json:"itemName"`
	Quantity     int                `bson:"quantity" json:"quantity"`
	Status       RequistionStatus   `bson:"status" json:"status"`
	CreatedAt    time.Time          `bson:"createdAt" json:"createdAt"`
}
