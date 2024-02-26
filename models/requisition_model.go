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
	ID primitive.ObjectID `bson:"_id,omitempty"`

	DepartmentId primitive.ObjectID `bson:"departmentId"`
	ItemName     string             `bson:"itemName"`
	Quantity     int                `bson:"quantity"`
	Status       RequistionStatus   `bson:"status"`
	CreatedAt    time.Time          `bson:"createdAt"`
}
