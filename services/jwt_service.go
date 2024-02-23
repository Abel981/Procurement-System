package services

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)
   
   type Role string

const (
	MainAdmin       Role = "main admin"
	DepartmentAdmin Role = "department admin"
	User            Role = "user"
)

type JwtCustomClaims struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      Role   `json:"role"`
	jwt.RegisteredClaims
	
}
   var secretKey = []byte("secret-key")
   
   func CreateToken(claim JwtCustomClaims) (string, error) {
	   token := jwt.NewWithClaims(jwt.SigningMethodHS256, 
		  &JwtCustomClaims{ 
		   claim.FirstName, 
		  claim.LastName,
		   claim.Role,
				jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
				},
		   })
   
	   tokenString, err := token.SignedString(secretKey)
	   if err != nil {
	   return "", err
	   }
   
	return tokenString, nil
   }

   func VerifyToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
	   return secretKey, nil
	})
   
	if err != nil {
	   return err
	}
   
	if !token.Valid {
	   return fmt.Errorf("invalid token")
	}
   
	return nil
 }

 func ParseToken(token string) *JwtCustomClaims {
	parsedAccessToken, _ := jwt.ParseWithClaims(token, &JwtCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
	 return secretKey, nil
	})
   
	return parsedAccessToken.Claims.(*JwtCustomClaims)
   }