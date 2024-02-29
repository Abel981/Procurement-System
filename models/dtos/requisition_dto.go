package dtos

type CreateRequistionDto struct {
	// DepartmentId primitive.ObjectID      `bson:"departmentId"`
	ItemName string `bson:"itemName" json:"itemName" validate:"required"`
	Quantity int    `bson:"quantity" json:"quantity" validate:"required"`
}
