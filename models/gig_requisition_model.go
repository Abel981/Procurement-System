package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type GigRequistion struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	GigId          primitive.ObjectID `bson:"gigId" json:"gigId"`
	DepartmentName string             `bson:"departmentName" json:"departmentName"`
	DepartmentId   primitive.ObjectID `bson:"departmentId" json:"departmentId"`
	Description    string             `bson:"description" json:"description"`
	Price          float64            `bson:"price" json:"price"`
	Quantity       int                `bson:"quantity" json:"quantity"`
	Status         RequistionStatus   `bson:"status" json:"status"`
	CreatedAt      time.Time          `bson:"createdAt" json:"createdAt"`
}
