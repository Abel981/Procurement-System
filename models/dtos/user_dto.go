package dtos

type UserSignupDTO struct {
	FirstName string `json:"firstName,omitempty" validate:"required"`
	LastName  string `json:"lastName,omitempty" validate:"required"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=6"`
	Country   string `json:"country" validate:"required"`

	ConfirmPassword string `json:"confirmPassword" validate:"required,eqfield=Password"`
}
