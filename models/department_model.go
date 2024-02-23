package models

import (
	"github.com/shopspring/decimal"
)

type Department struct {
	DepartmentName   string          `json:"department_name,omitempty" form:"department_name" validate:"required"`
	DepartmentBudget decimal.Decimal `json:"department_budget,omitempty" form:"department_bidget" validate:"required"`
	DepartmentAdmin  User `json:"department_admin,omitempty" form:"department_admin" bson:"departmentAdmin" `
}

type DepartmentAdmin struct {
	User
}
