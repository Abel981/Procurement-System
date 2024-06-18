package configs

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type emailCredential struct {
	Sender   string
	Password string
}
type cloudinaryCredential struct {
	CloudName string
	ApiKey    string
	ApiSecret string
}

func EnvMongoURI() string {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	return os.Getenv("MONGOURI")
}

func EnvEmailCredentials() emailCredential {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	return emailCredential{
		Sender:   os.Getenv("EMAIL_SENDER_NAME"),
		Password: os.Getenv("EMAIL_PASSWORD"),
	}
}
func EnvCloudinaryCredentials() cloudinaryCredential {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	return cloudinaryCredential{
		CloudName: os.Getenv("CLOUDINARY_CLOUD_NAME"),
		ApiKey:    os.Getenv("CLOUDINARY_KEY"),
		ApiSecret: os.Getenv("CLOUDINARY_SECRET"),
	}
}
