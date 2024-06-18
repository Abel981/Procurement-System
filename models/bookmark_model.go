package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Bookmark struct {
	Id           primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	SupplierId   primitive.ObjectID `bson:"supplierId,omitempty" json:"supplierId,omitempty"`
	RequistionId primitive.ObjectID `bson:"requistionId,omitempty" json:"requistionId,omitempty"`
	CreatedAt    time.Time          `bson:"createdAt" json:"createdAt"`
}
