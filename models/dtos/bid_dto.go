package dtos


type BidDto struct {
	RequistionId string `bson:"requistionId" json:"requistionId" validate:"required"`
	Price        float64            `bson:"price" json:"price"`
}
