// Copyright 2021 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authservice

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/rokwire/core-auth-library-go/authutils"
	"golang.org/x/sync/syncmap"
	"gopkg.in/go-playground/validator.v9"
)

// -------------------- AuthService --------------------

// AuthService contains the configurations needed to interface with the auth service
type AuthService struct {
	ServiceID   string // ID of implementing service
	ServiceHost string // Host of the implementing service
	FirstParty  bool   // Whether the implementing service is a first party member of the ROKWIRE platform
	AuthBaseURL string // Base URL where auth service resources are located
}

func checkAuthService(as *AuthService, requireBaseURL bool) error {
	if as == nil {
		return errors.New("auth service is missing")
	}

	if as.ServiceID == "" {
		return errors.New("service ID is missing")
	}
	if as.ServiceHost == "" {
		return errors.New("service host is missing")
	}

	if requireBaseURL && as.AuthBaseURL == "" {
		return errors.New("auth base URL is missing")
	}

	return nil
}

// -------------------- ServiceRegManager --------------------

// ServiceRegManager declares an object to manage service registrations
type ServiceRegManager struct {
	AuthService *AuthService

	services        *syncmap.Map
	servicesUpdated *time.Time // Most recent time the services cache was updated
	servicesLock    *sync.RWMutex

	minRefreshCacheFreq uint // Minimum refresh frequency for cached service registration records (minutes)
	maxRefreshCacheFreq uint // Maximum refresh frequency for cached service registration records (minutes)

	loader ServiceRegLoader
}

// GetServiceReg returns the service registration record for the given ID if found
func (s *ServiceRegManager) GetServiceReg(id string) (*ServiceReg, error) {
	s.servicesLock.RLock()
	servicesUpdated := s.servicesUpdated
	maxRefreshFreq := s.maxRefreshCacheFreq
	s.servicesLock.RUnlock()

	var loadServicesError error
	now := time.Now()
	if servicesUpdated == nil || now.Sub(*servicesUpdated).Minutes() > float64(maxRefreshFreq) {
		loadServicesError = s.LoadServices()
	}

	var service ServiceReg

	if s.services == nil {
		return nil, fmt.Errorf("services could not be loaded: %v", loadServicesError)
	}
	itemValue, ok := s.services.Load(id)
	if !ok {
		return nil, fmt.Errorf("service could not be found for id: %s - %v", id, loadServicesError)
	}

	service, ok = itemValue.(ServiceReg)
	if !ok {
		return nil, fmt.Errorf("service could not be parsed for id: %s - %v", id, loadServicesError)
	}

	return &service, loadServicesError
}

// GetServiceRegWithPubKey returns the service registration record for the given ID if found and validates the PubKey
func (s *ServiceRegManager) GetServiceRegWithPubKey(id string) (*ServiceReg, error) {
	serviceReg, err := s.GetServiceReg(id)
	if err != nil || serviceReg == nil {
		return nil, fmt.Errorf("failed to retrieve service reg: %v", err)
	}

	if serviceReg.PubKey == nil {
		return nil, fmt.Errorf("service pub key is nil for id %s", id)
	}

	if serviceReg.PubKey.Key == nil {
		err = serviceReg.PubKey.LoadKeyFromPem()
		if err != nil || serviceReg.PubKey.Key == nil {
			return nil, fmt.Errorf("service pub key is invalid for id %s: %v", id, err)
		}
	}

	return serviceReg, nil
}

// LoadServices loads the subscribed service registration records and caches them
// 	This function will be called periodically after refreshCacheFreq, but can be called directly to force a cache refresh
func (s *ServiceRegManager) LoadServices() error {
	services, loadServicesError := s.loader.LoadServices()
	if services != nil {
		s.setServices(services)
	}
	return loadServicesError
}

// SubscribeServices subscribes to the provided services
//	If reload is true and one of the services is not already subscribed, the service registrations will be reloaded immediately
func (s *ServiceRegManager) SubscribeServices(serviceIDs []string, reload bool) error {
	newSub := false

	for _, serviceID := range serviceIDs {
		subscribed := s.loader.SubscribeService(serviceID)
		if subscribed {
			newSub = true
		}
	}

	if reload && newSub {
		err := s.LoadServices()
		if err != nil {
			return fmt.Errorf("error loading service registrations: %v", err)
		}
	}

	return nil
}

// UnsubscribeServices unsubscribes from the provided services
func (s *ServiceRegManager) UnsubscribeServices(serviceIDs []string) {
	for _, serviceID := range serviceIDs {
		s.loader.UnsubscribeService(serviceID)
	}
}

// ValidateServiceRegistration validates that the implementing service has a valid registration for the provided hostname
func (s *ServiceRegManager) ValidateServiceRegistration() error {
	service, err := s.GetServiceReg(s.AuthService.ServiceID)
	if err != nil || service == nil {
		return fmt.Errorf("no service registration found with id %s: %v", s.AuthService.ServiceID, err)
	}

	if s.AuthService.ServiceHost != service.Host {
		return fmt.Errorf("service host (%s) does not match expected value (%s) for id %s", service.Host, s.AuthService.ServiceHost, s.AuthService.ServiceID)
	}

	return nil
}

// ValidateServiceRegistrationKey validates that the implementing service has a valid registration for the provided keypair
func (s *ServiceRegManager) ValidateServiceRegistrationKey(privKey *rsa.PrivateKey) error {
	if privKey == nil {
		return errors.New("provided priv key is nil")
	}

	service, err := s.GetServiceRegWithPubKey(s.AuthService.ServiceID)
	if err != nil {
		return fmt.Errorf("failed to retrieve service pub key: %v", err)
	}

	if service.PubKey.Key.Equal(privKey.PublicKey) {
		return fmt.Errorf("service pub key does not match for id %s", s.AuthService.ServiceID)
	}

	return nil
}

// SetMinRefreshCacheFreq sets the minimum frequency at which cached service registration records are refreshed in minutes
// 	The default value is 1
func (s *ServiceRegManager) SetMinRefreshCacheFreq(freq uint) {
	s.servicesLock.Lock()
	s.minRefreshCacheFreq = freq
	s.servicesLock.Unlock()
}

// SetMaxRefreshCacheFreq sets the maximum frequency at which cached service registration records are refreshed in minutes
// 	The default value is 60
func (s *ServiceRegManager) SetMaxRefreshCacheFreq(freq uint) {
	s.servicesLock.Lock()
	s.maxRefreshCacheFreq = freq
	s.servicesLock.Unlock()
}

// CheckForRefresh checks if the list of stored service registrations needs updating
func (s *ServiceRegManager) CheckForRefresh() (bool, error) {
	s.servicesLock.RLock()
	servicesUpdated := s.servicesUpdated
	minRefreshFreq := s.minRefreshCacheFreq
	s.servicesLock.RUnlock()

	var loadServicesError error
	now := time.Now()
	if servicesUpdated == nil || now.Sub(*servicesUpdated).Minutes() > float64(minRefreshFreq) {
		loadServicesError = s.LoadServices()
		return true, loadServicesError
	}
	return false, loadServicesError
}

func (s *ServiceRegManager) setServices(services []ServiceReg) {
	s.servicesLock.Lock()

	s.services = &syncmap.Map{}
	if len(services) > 0 {
		for _, service := range services {
			s.services.Store(service.ServiceID, service)
			s.services.Store(service.ServiceAccountID, service)
		}
	}

	time := time.Now()
	s.servicesUpdated = &time

	s.servicesLock.Unlock()
}

// NewServiceRegManager creates and configures a new ServiceRegManager instance
func NewServiceRegManager(authService *AuthService, serviceRegLoader ServiceRegLoader) (*ServiceRegManager, error) {
	err := checkAuthService(authService, false)
	if err != nil {
		return nil, fmt.Errorf("error checking auth service: %v", err)
	}

	if serviceRegLoader == nil {
		return nil, errors.New("service registration loader is missing")
	}

	lock := &sync.RWMutex{}
	services := &syncmap.Map{}

	manager := &ServiceRegManager{AuthService: authService, services: services, servicesLock: lock, minRefreshCacheFreq: 1, maxRefreshCacheFreq: 60,
		loader: serviceRegLoader}

	// Subscribe to the implementing service to validate registration
	serviceRegLoader.SubscribeService(authService.ServiceID)

	err = manager.LoadServices()
	if err != nil {
		return nil, fmt.Errorf("error loading services: %v", err)
	}

	err = manager.ValidateServiceRegistration()
	if err != nil {
		return nil, fmt.Errorf("unable to validate service registration: please contact the service registration system admin to register your service - %v", err)
	}

	return manager, nil
}

// NewTestServiceRegManager creates and configures a test ServiceRegManager instance
func NewTestServiceRegManager(authService *AuthService, serviceRegLoader ServiceRegLoader) (*ServiceRegManager, error) {
	err := checkAuthService(authService, false)
	if err != nil {
		return nil, fmt.Errorf("error checking auth service: %v", err)
	}

	if serviceRegLoader == nil {
		return nil, errors.New("service registration loader is missing")
	}

	lock := &sync.RWMutex{}
	services := &syncmap.Map{}

	manager := &ServiceRegManager{AuthService: authService, services: services, servicesLock: lock, minRefreshCacheFreq: 1, maxRefreshCacheFreq: 60,
		loader: serviceRegLoader}

	// Subscribe to the implementing service to validate registration
	serviceRegLoader.SubscribeService(authService.ServiceID)

	err = manager.LoadServices()
	if err != nil {
		return nil, fmt.Errorf("error loading services: %v", err)
	}

	return manager, nil
}

// -------------------- ServiceRegLoader --------------------

// ServiceRegLoader declares an interface to load the service registrations for specified services
type ServiceRegLoader interface {
	// LoadServices loads the service registration records for all subscribed services
	LoadServices() ([]ServiceReg, error)
	//GetSubscribedServices returns the list of currently subscribed services
	GetSubscribedServices() []string
	// SubscribeService subscribes the manager to the given service
	// 	Returns true if the specified service was added or false if it was already found
	SubscribeService(serviceID string) bool
	// UnsubscribeService unsubscribes the manager from the given service
	// 	Returns true if the specified service was removed or false if it was not found
	UnsubscribeService(serviceID string) bool
}

//RemoteServiceRegLoaderImpl provides a ServiceRegLoader implementation for a remote auth service
type RemoteServiceRegLoaderImpl struct {
	authService *AuthService

	path string // Path to service registrations resource on the auth service

	*ServiceRegSubscriptions
}

// LoadServices implements ServiceRegLoader interface
func (r *RemoteServiceRegLoaderImpl) LoadServices() ([]ServiceReg, error) {
	if len(r.GetSubscribedServices()) == 0 {
		return nil, nil
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", r.authService.AuthBaseURL+r.path, nil)
	if err != nil {
		return nil, fmt.Errorf("error formatting request to load services: %v", err)
	}

	servicesQuery := strings.Join(r.GetSubscribedServices(), ",")

	q := req.URL.Query()
	q.Add("ids", servicesQuery)
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error requesting services: %v", err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body of service response: %v", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error loading services: %d - %s", resp.StatusCode, string(body))
	}

	var services []ServiceReg
	err = json.Unmarshal(body, &services)
	if err != nil {
		return nil, fmt.Errorf("error on unmarshal service response: %v", err)
	}

	validate := validator.New()
	for _, service := range services {
		err = validate.Struct(service)
		if err != nil {
			return nil, fmt.Errorf("error validating service data: %v", err)
		}
		service.PubKey.LoadKeyFromPem()
	}

	return services, nil
}

// NewRemoteServiceRegLoader creates and configures a new RemoteServiceRegLoaderImpl instance
func NewRemoteServiceRegLoader(authService *AuthService, subscribedServices []string) (*RemoteServiceRegLoaderImpl, error) {
	err := checkAuthService(authService, true)
	if err != nil {
		return nil, fmt.Errorf("error checking auth service: %v", err)
	}

	path := "tps/service-regs"
	if authService.FirstParty {
		path = "bbs/service-regs"
	}

	subscriptions := NewServiceRegSubscriptions(subscribedServices)
	return &RemoteServiceRegLoaderImpl{authService: authService, path: path, ServiceRegSubscriptions: subscriptions}, nil
}

// -------------------- ServiceRegSubscriptions --------------------

// ServiceRegSubscriptions defined a struct to hold service registration subscriptions
// 	This struct implements the subcription part of the ServiceRegManager interface
//	If you subscribe to the reserved "all" service ID, all registered services
//	will be loaded
type ServiceRegSubscriptions struct {
	subscribedServices []string // Service registrations to load
	servicesLock       *sync.RWMutex
}

// GetSubscribedServices returns the list of subscribed services
func (r *ServiceRegSubscriptions) GetSubscribedServices() []string {
	r.servicesLock.RLock()
	defer r.servicesLock.RUnlock()

	return r.subscribedServices
}

// SubscribeService adds the given service ID to the list of subscribed services if not already present
// 	Returns true if the specified service was added or false if it was already found
func (r *ServiceRegSubscriptions) SubscribeService(serviceID string) bool {
	r.servicesLock.Lock()
	defer r.servicesLock.Unlock()

	if !authutils.ContainsString(r.subscribedServices, serviceID) {
		r.subscribedServices = append(r.subscribedServices, serviceID)
		return true
	}

	return false
}

// UnsubscribeService removed the given service ID from the list of subscribed services if presents
// 	Returns true if the specified service was removed or false if it was not found
func (r *ServiceRegSubscriptions) UnsubscribeService(serviceID string) bool {
	r.servicesLock.Lock()
	defer r.servicesLock.Unlock()

	services, removed := authutils.RemoveString(r.subscribedServices, serviceID)
	r.subscribedServices = services

	return removed
}

// NewServiceRegSubscriptions creates and configures a new ServiceRegSubscriptions instance
func NewServiceRegSubscriptions(subscribedServices []string) *ServiceRegSubscriptions {
	lock := &sync.RWMutex{}
	return &ServiceRegSubscriptions{subscribedServices: subscribedServices, servicesLock: lock}
}

// -------------------- ServiceAccountManager --------------------

// ServiceAccountManager declares an interface to manage data retrieved from an auth service
type ServiceAccountManager interface {
	// GetAccessToken gets an access token
	GetAccessToken() (*AccessToken, error)
	// CachedAccessToken returns a cached token
	CachedAccessToken() AccessToken
}

//RemoteServiceAccountManagerImpl provides a ServiceAccountManager implementation for a remote auth service
type RemoteServiceAccountManagerImpl struct {
	AuthService *AuthService

	accessToken AccessToken

	accessTokenPath string // Path to service account access token API

	config RemoteServiceAccountManagerConfig
}

//RemoteServiceAccountManagerConfig represents a configuration for a remote service account manager
type RemoteServiceAccountManagerConfig struct {
	AccountID string // Service account ID on the auth service
	Token     string // Static token issued by the auth service

	AccessTokenRequestFunc func(string, string, string, string) (*http.Request, error) // Function that builds access token request
}

// GetAccessToken implements ServiceAccountManager interface
func (r *RemoteServiceAccountManagerImpl) GetAccessToken() (*AccessToken, error) {
	if r.config.AccessTokenRequestFunc == nil {
		return nil, errors.New("access token request function is missing")
	}

	req, err := r.config.AccessTokenRequestFunc(r.AuthService.AuthBaseURL, r.accessTokenPath, r.config.AccountID, r.config.Token)
	if err != nil {
		return nil, fmt.Errorf("error creating access token request: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error requesting access token: %v", err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body of access token response: %v", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error getting access token: %d - %s", resp.StatusCode, string(body))
	}

	var token AccessToken
	err = json.Unmarshal(body, &token)
	if err != nil {
		return nil, fmt.Errorf("error on unmarshal access token response: %v", err)
	}

	r.accessToken = token

	return &token, nil
}

// CachedAccessToken returns the cached access token
func (r *RemoteServiceAccountManagerImpl) CachedAccessToken() AccessToken {
	return r.accessToken
}

// NewRemoteServiceAccountManager creates and configures a new RemoteServiceAccountManagerImpl instance for the provided config
func NewRemoteServiceAccountManager(authService *AuthService, config RemoteServiceAccountManagerConfig) (*RemoteServiceAccountManagerImpl, error) {
	err := checkAuthService(authService, true)
	if err != nil {
		return nil, fmt.Errorf("error checking auth service: %v", err)
	}

	err = checkServiceAccountManagerConfig(&config)
	if err != nil {
		return nil, fmt.Errorf("error checking service account manager config: %v", err)
	}

	accessTokenPath := "tps/access-token"
	if authService.FirstParty {
		accessTokenPath = "bbs/access-token"
	}

	dataManager := RemoteServiceAccountManagerImpl{AuthService: authService, accessTokenPath: accessTokenPath, config: config}
	return &dataManager, nil
}

func checkServiceAccountManagerConfig(config *RemoteServiceAccountManagerConfig) error {
	if config.AccountID == "" {
		return errors.New("service account ID is missing")
	}

	if config.AccessTokenRequestFunc == nil && config.Token != "" {
		config.AccessTokenRequestFunc = authutils.BuildDefaultAccessTokenRequest
	}

	return nil
}

// -------------------- AccessToken --------------------

// AccessToken represents an access token granted by a remote auth service
type AccessToken struct {
	Token     string `json:"access_token"`
	TokenType string `json:"token_type"`
}

// String returns the stored access token as a string
func (t AccessToken) String() string {
	return fmt.Sprintf("%s %s", t.TokenType, t.Token)
}

// -------------------- ServiceReg --------------------

// ServiceReg represents a service registration record
type ServiceReg struct {
	ServiceID        string  `json:"service_id" bson:"service_id" validate:"required"`
	ServiceAccountID string  `json:"service_account_id" bson:"service_account_id"`
	Host             string  `json:"host" bson:"host" validate:"required"`
	PubKey           *PubKey `json:"pub_key" bson:"pub_key"`
}

// -------------------- PubKey --------------------

// PubKey represents a public key object including the key and related metadata
type PubKey struct {
	Key    *rsa.PublicKey `json:"-" bson:"-"`
	KeyPem string         `json:"key_pem" bson:"key_pem" validate:"required"`
	Alg    string         `json:"alg" bson:"alg" validate:"required"`
	Kid    string         `json:"-" bson:"-"`
}

// LoadKeyFromPem parses "KeyPem" and sets the "Key" and "Kid"
func (p *PubKey) LoadKeyFromPem() error {
	if p == nil {
		return fmt.Errorf("pubkey is nil")
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(p.KeyPem))
	if err != nil {
		p.Key = nil
		p.Kid = ""
		return fmt.Errorf("error parsing key string: %v", err)
	}

	kid, err := authutils.GetKeyFingerprint(key)
	if err != nil {
		p.Key = nil
		p.Kid = ""
		return fmt.Errorf("error getting key fingerprint: %v", err)
	}

	p.Key = key
	p.Kid = kid

	return nil
}
