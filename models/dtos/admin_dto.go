package dtos

type AdminLoginDTO struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
}

type AddDepartmentDto struct {
	DepartmentName   string  `json:"department_name,omitempty" form:"department_name" validate:"required"`
	DepartmentBudget float64 `json:"department_budget,omitempty" form:"department_budget" validate:"required"`
}
