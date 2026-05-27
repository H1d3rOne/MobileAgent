package store

import (
	"errors"

	"github.com/mobileagent/backend-go/internal/model"
	"gorm.io/gorm"
)

type DeviceStore struct {
	store *Store
}

func NewDeviceStore(s *Store) *DeviceStore {
	return &DeviceStore{store: s}
}

func (ds *DeviceStore) List() ([]model.Device, error) {
	var devices []model.Device
	err := ds.store.DB.Find(&devices).Error
	return devices, err
}

func (ds *DeviceStore) Get(id string) (*model.Device, error) {
	var d model.Device
	err := ds.store.DB.Where("id = ?", id).First(&d).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &d, err
}

func (ds *DeviceStore) GetBySerial(serial string) (*model.Device, error) {
	var d model.Device
	err := ds.store.DB.Where("serial = ?", serial).First(&d).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &d, err
}

func (ds *DeviceStore) Create(d *model.Device) error {
	return ds.store.DB.Create(d).Error
}

func (ds *DeviceStore) Update(d *model.Device) error {
	return ds.store.DB.Save(d).Error
}

func (ds *DeviceStore) Delete(id string) error {
	return ds.store.DB.Where("id = ?", id).Delete(&model.Device{}).Error
}
