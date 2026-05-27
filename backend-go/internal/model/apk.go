package model

import "time"

type APK struct {
	ID             string    `json:"id" gorm:"primaryKey"`
	Filename       string    `json:"filename"`
	FilePath       string    `json:"file_path"`
	FileSize       int64     `json:"file_size"`
	PackageName    string    `json:"package_name,omitempty"`
	VersionName    string    `json:"version_name,omitempty"`
	VersionCode    int       `json:"version_code,omitempty"`
	MinSDK         int       `json:"min_sdk,omitempty"`
	TargetSDK      int       `json:"target_sdk,omitempty"`
	Permissions    string    `json:"permissions,omitempty" gorm:"type:text"`
	Activities     string    `json:"activities,omitempty" gorm:"type:text"`
	Status         string    `json:"status" gorm:"default:uploaded"`
	DecompiledTool string    `json:"decompiled_tool,omitempty"`
	DecompiledPath string    `json:"decompiled_path,omitempty"`
	DecompiledAt   *time.Time `json:"decompiled_at,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type APKAnalysis struct {
	ID          string    `json:"id" gorm:"primaryKey"`
	APKID       string    `json:"apk_id" gorm:"index"`
	Type        string    `json:"type"`
	Result      string    `json:"result,omitempty" gorm:"type:text"`
	CreatedAt   time.Time `json:"created_at"`
}
