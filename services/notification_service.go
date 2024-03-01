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
	Email string
	FirstName string
	LastName string
  }

  func SendEmail(reciversData []EmailRecipientData, templatePath string) error{
	  var body bytes.Buffer
	  t, _ := template.ParseFiles(templatePath)
	  var credentials = configs.EnvEmailCredentials()
	m := gomail.NewMessage()
	m.SetHeader("From", "abel.wen0@gmail.com")
	m.SetHeader("Subject", "Template Email Test")
	d := gomail.NewDialer("smtp.gmail.com", 587, credentials.Sender, credentials.Password)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	for _, receiverData := range reciversData {
		  t.Execute(&body, struct {
			  Name    string
			 
			}{
			  Name:    receiverData.FirstName + " " + receiverData.LastName,

			})
		m.SetHeader("To", receiverData.Email)
		m.SetBody("text/html", body.String())

		// Send the email
		if err := d.DialAndSend(m); err != nil {
			fmt.Println(err)
			panic(err)
		  }
	}

	return nil
  }