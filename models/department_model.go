package models

import (
	// "github.com/shopspring/decimal"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Department struct {
	ID               primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	DepartmentName   string             `json:"departmentName,omitempty" form:"departmentName" validate:"required"`
	DepartmentBudget float32    `json:"departmentBudget,omitempty" form:"departmentBudget" validate:"required"`
	DepartmentAdminId  string               `json:"departmentAdminId,omitempty" form:"departmentAdminId" bson:"departmentAdminId" `
}

type DepartmentAdmin struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Email          string             `json:"email,omitempty" validate:"required"`
	FirstName      string             `json:"first_name,omitempty" validate:"required"`
	LastName       string             `json:"last_name,omitempty" validate:"required"`
	HashedPassword string             `json:"hashed_password"`
	Role           Role               `json:"role,omitempty" validate:"required"`
	DepartmentId   primitive.ObjectID            `json:"departmentId,omitempty" form:"department_name" validate:"required"`
}
