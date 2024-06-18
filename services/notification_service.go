package services

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"procrument-system/configs"
	"text/template"

	gomail "gopkg.in/gomail.v2"
)

type EmailRecipientData struct {
	Id string
	Email     string
	FirstName string
	LastName  string
	ResetPasswordText string
}

func SendEmail(receiverData EmailRecipientData, templatePath string) error {
	var body bytes.Buffer

	t, err := template.ParseFiles(templatePath)
	if err != nil {
		fmt.Println("Error", err)
	}

	var credentials = configs.EnvEmailCredentials()
	m := gomail.NewMessage()

	

	m.SetHeader("From", "abel.wen0@gmail.com")
	m.SetHeader("Subject", "Template Email Test")
	d := gomail.NewDialer("smtp.gmail.com", 587, credentials.Sender, credentials.Password)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}
fmt.Println("mm1")
	t.Execute(&body, struct {
		Id string
		Name string
		ResetPasswordText string
	}{
		Name: receiverData.FirstName + " " + receiverData.LastName,
		Id: receiverData.Id,
		ResetPasswordText: receiverData.ResetPasswordText,
	})
	fmt.Println("mm2")
	m.SetHeader("To", receiverData.Email)
	m.SetBody("text/html", body.String())

	// Send the email
	if err := d.DialAndSend(m); err != nil {
		fmt.Println(err)
		fmt.Println("mm3")
		panic(err)
	}

	return nil
}
