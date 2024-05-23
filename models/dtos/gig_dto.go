package dtos

type GigDto struct {
	Title       string  `json:"title" form:"title" validate:"required"`
	Price       float64 `json:"price" form:"price" validate:"required"`
	Description string  `json:"description" form:"description" validate:"required"`
}
