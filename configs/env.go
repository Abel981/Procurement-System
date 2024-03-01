package configs

import (
    "log"
    "os"
    "github.com/joho/godotenv"
)

type emailCredential struct {
    Sender string
    Password string
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
        Sender: os.Getenv("EMAIL_SENDER_NAME"),
        Password: os.Getenv("EMAIL_PASSWORD"),
    }
}