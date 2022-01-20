package models

import "time"

type Book struct {
	ID          uint   `json:"id" gorm:"primaryKey;not null"`
	Name        string `json:"Name" gorm:"size:500;not null"`
	Image       string `json:"image" `
	Description string `json:"Description"`
	Account_ID  uint
	Account     Account `json:"Account" gorm:"foreignKey:Account_ID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

type Account struct {
	ID         uint      `json:"id" gorm:"primaryKey;not null"`
	Email      string    `json:"email" gorm:"size:500;not null"`
	Firstname  string    `json:"firstname" gorm:"size:500"`
	Lastname   string    `json:"lastname" gorm:"size:500"`
	Password   string    `json:"password" gorm:"size:500;not null"`
	Created_on time.Time `json:"create_on" gorm:"default:now()"`
	Isadmin    bool      `json:"isadmin" gorm:"default:false"`
}
