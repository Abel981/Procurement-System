package dtos


type CreateRequistionDto struct {
	// DepartmentId primitive.ObjectID      `bson:"departmentId"`
	ItemName string `bson:"itemName" json:"itemName" validate:"required"`
	Description string `bson:"description" json:"description" validate:"required"`
	Quantity int    `bson:"quantity" json:"quantity" validate:"required"`
	Price float64 `bson:"price" json:"price" validate:"required"`

}

type CreateGigRequistionDto struct {
	// DepartmentId primitive.ObjectID      `bson:"departmentId"`
	GigId          string`bson:"gigId" json:"gigId"`
	Price          float64            `bson:"price" json:"price"`
	Description string `bson:"description" json:"description" validate:"required"`
	Quantity int    `bson:"quantity" json:"quantity" validate:"required"`
	

}
