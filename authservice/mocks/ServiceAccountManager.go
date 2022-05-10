// Code generated by mockery v2.10.0. DO NOT EDIT.

package mocks

import (
	authservice "github.com/rokwire/core-auth-library-go/authservice"
	mock "github.com/stretchr/testify/mock"
)

// ServiceAccountManager is an autogenerated mock type for the ServiceAccountManager type
type ServiceAccountManager struct {
	mock.Mock
}

// GetAccessToken provides a mock function with given fields:
func (_m *ServiceAccountManager) GetAccessToken() (*authservice.AccessToken, error) {
	ret := _m.Called()

	var r0 *authservice.AccessToken
	if rf, ok := ret.Get(0).(func() *authservice.AccessToken); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*authservice.AccessToken)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

func NewServiceAccountManager() *ServiceAccountManager {
	return &ServiceAccountManager{}
}
