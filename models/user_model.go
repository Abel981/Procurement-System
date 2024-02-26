package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Role string

type User struct {
	ID             primitive.ObjectID `bson:"_id,omitempty"`
	Email          string             `json:"email,omitempty" validate:"required"`
	FirstName      string             `json:"first_name,omitempty" validate:"required"`
	LastName       string             `json:"last_name,omitempty" validate:"required"`
	HashedPassword string             `json:"hashed_password"`
	Role           Role               `json:"role,omitempty" validate:"required"`
}
