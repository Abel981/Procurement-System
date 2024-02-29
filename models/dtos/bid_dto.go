package dtos


type BidDto struct {
	RequistionId string `bson:"requistionId"`
	Price        float64            `bson:"price"`
}
