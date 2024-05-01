package dtos



type BidDto struct {
	RequistionId string                `bson:"requistionId" json:"requistionId" form:"requistionId" validate:"required"`
	Price        float64               `bson:"price" json:"price" form:"price" validate:"required"`
	
}
