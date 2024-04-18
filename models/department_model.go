package models

import (
	// "github.com/shopspring/decimal"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Department struct {
	ID               primitive.ObjectID `bson:"_id,omitempty"`
	DepartmentName   string             `json:"departmentName,omitempty" form:"departmentName" validate:"required"`
	DepartmentBudget int    `json:"departmentBudget,omitempty" form:"departmentBudget" validate:"required"`
	DepartmentAdmin  User               `json:"departmentAdmin,omitempty" form:"departmentAdmin" bson:"departmentAdmin" `
}

type DepartmentAdmin struct {
	User
	DepartmentId   primitive.ObjectID            `json:"departmentId,omitempty" form:"department_name" validate:"required"`
}
