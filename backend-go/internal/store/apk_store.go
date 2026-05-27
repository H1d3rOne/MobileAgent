package store

import (
	"errors"

	"github.com/mobileagent/backend-go/internal/model"
	"gorm.io/gorm"
)

type APKStore struct {
	store *Store
}

func NewAPKStore(s *Store) *APKStore {
	return &APKStore{store: s}
}

func (as *APKStore) List() ([]model.APK, error) {
	var apks []model.APK
	err := as.store.DB.Find(&apks).Error
	return apks, err
}

func (as *APKStore) Get(id string) (*model.APK, error) {
	var a model.APK
	err := as.store.DB.Where("id = ?", id).First(&a).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &a, err
}

func (as *APKStore) Create(a *model.APK) error {
	return as.store.DB.Create(a).Error
}

func (as *APKStore) Update(a *model.APK) error {
	return as.store.DB.Save(a).Error
}

func (as *APKStore) Delete(id string) error {
	return as.store.DB.Where("id = ?", id).Delete(&model.APK{}).Error
}

func (as *APKStore) FindByPath(path string) (*model.APK, error) {
	var a model.APK
	err := as.store.DB.Where("file_path = ?", path).First(&a).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &a, err
}

func (as *APKStore) CreateAnalysis(a *model.APKAnalysis) error {
	return as.store.DB.Create(a).Error
}

func (as *APKStore) ListAnalysis(apkID string) ([]model.APKAnalysis, error) {
	var results []model.APKAnalysis
	err := as.store.DB.Where("apk_id = ?", apkID).Find(&results).Error
	return results, err
}

func (as *APKStore) GetAnalysisByType(apkID, typ string) (*model.APKAnalysis, error) {
	var a model.APKAnalysis
	err := as.store.DB.Where("apk_id = ? AND type = ?", apkID, typ).Order("created_at DESC").First(&a).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &a, err
}

func (as *APKStore) UpsertAnalysis(a *model.APKAnalysis) error {
	if err := as.store.DB.Where("apk_id = ? AND type = ?", a.APKID, a.Type).Delete(&model.APKAnalysis{}).Error; err != nil {
		return err
	}
	return as.store.DB.Create(a).Error
}
