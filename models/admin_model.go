package models



type Admin struct {
	
	Email string `json:"email,omitempty" validate:"required"`
	FirstName string             `json:"first_name,omitempty" validate:"required"`
	LastName  string             `json:"last_name,omitempty" validate:"required"`
	HashedPassword string `json:"hashed_password,omitempty" validate:"required"`
	Role Role `json:"role,omitempty" validate:"required"`

}
