package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Bid struct {
	ID           primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	SupplierId   primitive.ObjectID `bson:"supplierId" json:"supplierId"`
	RequistionId primitive.ObjectID `bson:"requistionId" json:"requistionId"`
	Price        float64            `bson:"price" json:"price"`
	Status       RequistionStatus   `bson:"status"  json:"status"`
	CreatedAt    time.Time          `bson:"createdAt" json:"createdAt"`
	DocumentUrl string `bson:"documentUrl" json:"documentUrl"`
	
}
