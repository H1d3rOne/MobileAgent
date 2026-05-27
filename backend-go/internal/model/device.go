package model

import "time"

type Device struct {
	ID              string    `json:"id" gorm:"primaryKey"`
	Serial          string    `json:"serial" gorm:"uniqueIndex"`
	Model           string    `json:"model,omitempty"`
	Brand           string    `json:"brand,omitempty"`
	AndroidVersion  string    `json:"android_version,omitempty"`
	SDKVersion      int       `json:"sdk_version,omitempty"`
	IPAddress       string    `json:"ip_address,omitempty"`
	Port            int       `json:"port,omitempty"`
	Status          string    `json:"status" gorm:"default:offline"`
	ScreenWidth     int       `json:"screen_width,omitempty"`
	ScreenHeight    int       `json:"screen_height,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}
