package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Offering represents a product or service offered by the supplier
// type Offering struct {
// 	ProductID   string   `json:"product_id"`
// 	Price       float64  `json:"price"`
// 	Description string   `json:"description"`
// 	Images      []string `json:"images"`
// }

// Gig represents a gig promoting supplier offerings
type Gig struct {
	Id          primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	SupplierID  primitive.ObjectID `bson:"supplierId,omitempty" json:"supplierId"`
	Title       string             `bson:"title,omitempty" json:"title"`
	ImagesUrl   []string           `bson:"imagesUrl" json:"imagesUrl"`
	Price       float64            `bson:"price" json:"price"`
	Description string             `bson:"description" json:"description"`
	CreatedAt   time.Time          `bson:"createdAt" json:"createdAt"`
}
