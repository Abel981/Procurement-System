package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)


type VerificationData struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	Email          string             `json:"email,omitempty" validate:"required"`
	Code      string             `json:"code,omitempty" validate:"required"`
	Type      string             `json:"type,omitempty" validate:"required"`
	ExpiresAt    time.Time          `bson:"expiresAt" json:"expiresAt"`
}