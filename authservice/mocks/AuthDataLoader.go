// Code generated by mockery v0.0.0-dev. DO NOT EDIT.

package mocks

import (
	authservice "github.com/rokwire/core-auth-library-go/authservice"
	mock "github.com/stretchr/testify/mock"
)

// AuthDataLoader is an autogenerated mock type for the AuthDataLoader type
type AuthDataLoader struct {
	mock.Mock

	authServicesHost string
	serviceToken     string
	accessToken      authservice.AccessToken

	*ServiceRegLoader
}

// GetAccessToken provides a mock function with given fields: path
func (_m *AuthDataLoader) GetAccessToken(path string) error {
	ret := _m.Called(path)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(path)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetDeletedAccounts provides a mock function with given fields: path
func (_m *AuthDataLoader) GetDeletedAccounts(path string) ([]string, error) {
	ret := _m.Called(path)

	var r0 []string
	if rf, ok := ret.Get(0).(func(string) []string); ok {
		r0 = rf(path)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(path)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

func NewAuthDataLoader(authServicesHost string, serviceToken string, serviceRegPath string, subscribedServices []string) *AuthDataLoader {
	serviceRegLoader := NewServiceRegLoader(serviceRegPath, subscribedServices)

	dataLoader := AuthDataLoader{authServicesHost: authServicesHost, serviceToken: serviceToken, ServiceRegLoader: serviceRegLoader}
	serviceRegLoader.dataLoader = &dataLoader

	return &dataLoader
}
