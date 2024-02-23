package dtos

type UserSignupDTO struct {
	FirstName       string `json:"first_name,omitempty" validate:"required"`
	LastName        string `json:"last_name,omitempty" validate:"required"`
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,min=6"`
	ConfirmPassword string `json:"confirm_password" validate:"required,eqfield=Password"`
	
}
