package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Bid struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	SupplierId   primitive.ObjectID `bson:"supplierId"`
	RequistionId primitive.ObjectID `bson:"requistionId"`
	Price        float64            `bson:"price"`
	Status       RequistionStatus   `bson:"status"`
	CreatedAt    time.Time          `bson:"createdAt"`
}
