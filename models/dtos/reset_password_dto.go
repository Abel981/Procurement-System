package dtos

type ResetPasswordVerificationDto struct {
	Code      string             `json:"code,omitempty" validate:"required"`
	Type      string             `json:"type,omitempty" validate:"required"`
	

}

type ResetPasswordDto struct {
	Password string `json:"password" validate:"required,min=6"`
	ConfirmPassword string `json:"confirmPassword" validate:"required,min=6"`
}