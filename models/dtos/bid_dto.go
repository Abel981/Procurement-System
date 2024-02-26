package dtos

import "go.mongodb.org/mongo-driver/bson/primitive"

type BidDto struct {
	RequistionId primitive.ObjectID `bson:"requistionId"`
	Price        float64            `bson:"price"`
}
