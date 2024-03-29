// Code generated by mockery v2.10.0. DO NOT EDIT.

package mocks

import (
	authservice "github.com/rokwire/core-auth-library-go/v3/authservice"
	mock "github.com/stretchr/testify/mock"
)

// ServiceAccountLoader is an autogenerated mock type for the ServiceAccountLoader type
type ServiceAccountLoader struct {
	mock.Mock
	authService *authservice.AuthService
}

// LoadAccessToken provides a mock function with given fields: appID, orgID
func (_m *ServiceAccountLoader) LoadAccessToken(appID string, orgID string) (*authservice.AccessToken, error) {
	ret := _m.Called(appID, orgID)

	var r0 *authservice.AccessToken
	if rf, ok := ret.Get(0).(func(string, string) *authservice.AccessToken); ok {
		r0 = rf(appID, orgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*authservice.AccessToken)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(appID, orgID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LoadAccessTokens provides a mock function with given fields:
func (_m *ServiceAccountLoader) LoadAccessTokens() (map[authservice.AppOrgPair]authservice.AccessToken, error) {
	ret := _m.Called()

	var r0 map[authservice.AppOrgPair]authservice.AccessToken
	if rf, ok := ret.Get(0).(func() map[authservice.AppOrgPair]authservice.AccessToken); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[authservice.AppOrgPair]authservice.AccessToken)
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

func NewServiceAccountLoader(authService *authservice.AuthService) *ServiceAccountLoader {
	return &ServiceAccountLoader{authService: authService}
}
