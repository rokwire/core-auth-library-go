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

// -------------------- ServiceAccountManager --------------------

// ServiceAccountManager declares an interface to manage data retrieved from a service account host
type ServiceAccountManager interface {
	// GetAccessToken gets an access token
	GetAccessToken() (*AccessToken, error)
	// CachedAccessToken returns a cached token
	CachedAccessToken() AccessToken
}

//RemoteServiceAccountManagerImpl provides a ServiceAccountManager implementation for a remote service account host
type RemoteServiceAccountManagerImpl struct {
	accessToken AccessToken

	config RemoteServiceAccountManagerConfig
}

//RemoteServiceAccountManagerConfig represents a configuration for a remote service account manager
type RemoteServiceAccountManagerConfig struct {
	ServiceAccountHost string // URL of service account host
	AccountID          string // Service account ID on the service account host
	Token              string // Static token issued by the service account host

	AccessTokenPath        string                                                      // Path to service account access token API
	AccessTokenRequestFunc func(string, string, string, string) (*http.Request, error) // Function that builds access token request
}

// GetAccessToken implements ServiceAccountManager interface
func (r *RemoteServiceAccountManagerImpl) GetAccessToken() (*AccessToken, error) {
	if r.config.AccessTokenRequestFunc == nil {
		return nil, errors.New("access token request function is missing")
	}

	req, err := r.config.AccessTokenRequestFunc(r.config.ServiceAccountHost, r.config.AccessTokenPath, r.config.AccountID, r.config.Token)
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
func NewRemoteServiceAccountManager(config RemoteServiceAccountManagerConfig, firstParty bool) (*RemoteServiceAccountManagerImpl, error) {
	err := checkServiceAccountManagerConfig(&config, firstParty)
	if err != nil {
		return nil, fmt.Errorf("error checking service account manager config: %v", err)
	}

	dataManager := RemoteServiceAccountManagerImpl{config: config}
	return &dataManager, nil
}

func checkServiceAccountManagerConfig(config *RemoteServiceAccountManagerConfig, firstParty bool) error {
	if config.ServiceAccountHost == "" {
		return errors.New("service account host is missing")
	}

	if config.AccessTokenPath == "" {
		if firstParty {
			config.AccessTokenPath = "/bbs/access-token"
		} else {
			config.AccessTokenPath = "/tps/access-token"
		}
	}

	if config.AccessTokenRequestFunc == nil && config.AccountID != "" && config.Token != "" {
		config.AccessTokenRequestFunc = authutils.BuildDefaultAccessTokenRequest
	}

	return nil
}

// -------------------- ServiceRegManager --------------------

// ServiceRegManager declares an interface to load the service registrations for specified services
type ServiceRegManager interface {
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

//RemoteServiceRegManagerImpl provides a ServiceRegManager implementation for a remote service registration host
type RemoteServiceRegManagerImpl struct {
	services        *syncmap.Map
	servicesUpdated *time.Time
	servicesLock    *sync.RWMutex

	config RemoteServiceRegManagerConfig

	*ServiceRegSubscriptions
}

//RemoteServiceRegManagerConfig represents a configuration for a remote service registration manager
type RemoteServiceRegManagerConfig struct {
	ServiceRegHost string // URL of service registration host
	ServiceID      string // ID of implementing service

	Path string // Path to service registration API

	MinRefreshCacheFreq uint // Minimum frequency at which cached service registration records are refreshed (minutes)
	MaxRefreshCacheFreq uint // Maximum frequency at which cached service registration records are refreshed (minutes)
}

// LoadServices implements ServiceRegManager interface
// 	This function will be called periodically after refreshCacheFreq, but can be called directly to force a cache refresh
func (r *RemoteServiceRegManagerImpl) LoadServices() ([]ServiceReg, error) {
	if len(r.GetSubscribedServices()) == 0 {
		return nil, nil
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", r.config.ServiceRegHost+r.config.Path, nil)
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

	r.setServices(services)

	return services, nil
}

// GetServiceReg returns the service registration record for the given ID if found
func (r *RemoteServiceRegManagerImpl) GetServiceReg(id string) (*ServiceReg, error) {
	r.servicesLock.RLock()
	servicesUpdated := r.servicesUpdated
	maxRefreshFreq := r.config.MaxRefreshCacheFreq
	r.servicesLock.RUnlock()

	var loadServicesError error
	now := time.Now()
	if servicesUpdated == nil || now.Sub(*servicesUpdated).Minutes() > float64(maxRefreshFreq) {
		_, loadServicesError = r.LoadServices()
	}

	var service ServiceReg

	if r.services == nil {
		return nil, fmt.Errorf("services could not be loaded: %v", loadServicesError)
	}
	itemValue, ok := r.services.Load(id)
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
func (r *RemoteServiceRegManagerImpl) GetServiceRegWithPubKey(id string) (*ServiceReg, error) {
	serviceReg, err := r.GetServiceReg(id)
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

// SubscribeServices subscribes to the provided services
//	If reload is true and one of the services is not already subscribed, the service registrations will be reloaded immediately
func (r *RemoteServiceRegManagerImpl) SubscribeServices(serviceIDs []string, reload bool) error {
	newSub := false

	for _, serviceID := range serviceIDs {
		subscribed := r.SubscribeService(serviceID)
		if subscribed {
			newSub = true
		}
	}

	if reload && newSub {
		_, err := r.LoadServices()
		if err != nil {
			return fmt.Errorf("error loading service registrations: %v", err)
		}
	}

	return nil
}

// UnsubscribeServices unsubscribes from the provided service
func (r *RemoteServiceRegManagerImpl) UnsubscribeServices(serviceIDs []string) {
	for _, serviceID := range serviceIDs {
		r.UnsubscribeService(serviceID)
	}
}

// ValidateServiceRegistration validates that the implementing service has a valid registration for the provided service ID and hostname
func (r *RemoteServiceRegManagerImpl) ValidateServiceRegistration(serviceHost string) error {
	service, err := r.GetServiceReg(r.config.ServiceID)
	if err != nil || service == nil {
		return fmt.Errorf("no service registration found with id %s: %v", r.config.ServiceID, err)
	}

	if serviceHost != service.Host {
		return fmt.Errorf("service host (%s) does not match expected value (%s) for id %s", service.Host, serviceHost, r.config.ServiceID)
	}

	return nil
}

// ValidateServiceRegistrationKey validates that the implementing service has a valid registration for the provided keypair
func (r *RemoteServiceRegManagerImpl) ValidateServiceRegistrationKey(privKey *rsa.PrivateKey) error {
	if privKey == nil {
		return errors.New("provided priv key is nil")
	}

	service, err := r.GetServiceRegWithPubKey(r.config.ServiceID)
	if err != nil {
		return fmt.Errorf("failed to retrieve service pub key: %v", err)
	}

	if service.PubKey.Key.Equal(privKey.PublicKey) {
		return fmt.Errorf("service pub key does not match for id %s", r.config.ServiceID)
	}

	return nil
}

// SetMinRefreshCacheFreq sets the minimum frequency at which cached service registration records are refreshed in minutes
// 	The default value is 1
func (r *RemoteServiceRegManagerImpl) SetMinRefreshCacheFreq(freq uint) {
	r.servicesLock.Lock()
	r.config.MinRefreshCacheFreq = freq
	r.servicesLock.Unlock()
}

// SetMaxRefreshCacheFreq sets the maximum frequency at which cached service registration records are refreshed in minutes
// 	The default value is 60
func (r *RemoteServiceRegManagerImpl) SetMaxRefreshCacheFreq(freq uint) {
	r.servicesLock.Lock()
	r.config.MaxRefreshCacheFreq = freq
	r.servicesLock.Unlock()
}

// CheckForRefresh checks if the list of stored service registrations needs updating
func (r *RemoteServiceRegManagerImpl) CheckForRefresh() (bool, error) {
	r.servicesLock.RLock()
	servicesUpdated := r.servicesUpdated
	minRefreshFreq := r.config.MinRefreshCacheFreq
	r.servicesLock.RUnlock()

	var loadServicesError error
	now := time.Now()
	if servicesUpdated == nil || now.Sub(*servicesUpdated).Minutes() > float64(minRefreshFreq) {
		_, loadServicesError = r.LoadServices()
		return true, loadServicesError
	}
	return false, loadServicesError
}

func (r *RemoteServiceRegManagerImpl) setServices(services []ServiceReg) {
	r.servicesLock.Lock()

	r.services = &syncmap.Map{}
	if len(services) > 0 {
		for _, service := range services {
			r.services.Store(service.ServiceID, service)
			r.services.Store(service.ServiceAccountID, service)
		}
	}

	time := time.Now()
	r.servicesUpdated = &time

	r.servicesLock.Unlock()
}

// NewRemoteServiceRegManager creates and configures a new RemoteServiceRegManagerImpl instance for the provided config
func NewRemoteServiceRegManager(config RemoteServiceRegManagerConfig, serviceHost string, subscribedServices []string, firstParty bool) (*RemoteServiceRegManagerImpl, error) {
	err := checkServiceRegManagerConfig(&config, firstParty)
	if err != nil {
		return nil, fmt.Errorf("error checking service registration manager config: %v", err)
	}

	lock := &sync.RWMutex{}
	services := &syncmap.Map{}

	subscriptions := NewServiceRegSubscriptions(subscribedServices)
	dataManager := &RemoteServiceRegManagerImpl{services: services, servicesLock: lock, config: config, ServiceRegSubscriptions: subscriptions}

	// Subscribe to the implementing service to validate registration
	dataManager.SubscribeService(config.ServiceID)

	_, err = dataManager.LoadServices()
	if err != nil {
		return nil, fmt.Errorf("error loading services: %v", err)
	}

	err = dataManager.ValidateServiceRegistration(serviceHost)
	if err != nil {
		return nil, fmt.Errorf("unable to validate service registration: please contact the service registration system admin to register your service - %v", err)
	}

	return dataManager, nil
}

// NewTestServiceRegManager creates and configures a test RemoteServiceRegManagerImpl instance
func NewTestServiceRegManager(config RemoteServiceRegManagerConfig, subscribedServices []string, firstParty bool) (*RemoteServiceRegManagerImpl, error) {
	err := checkServiceRegManagerConfig(&config, firstParty)
	if err != nil {
		return nil, fmt.Errorf("error checking service registration manager config: %v", err)
	}

	lock := &sync.RWMutex{}
	services := &syncmap.Map{}

	subscriptions := NewServiceRegSubscriptions(subscribedServices)
	dataManager := &RemoteServiceRegManagerImpl{services: services, servicesLock: lock, config: config, ServiceRegSubscriptions: subscriptions}

	// Subscribe to the implementing service to validate registration
	dataManager.SubscribeService(config.ServiceID)

	_, err = dataManager.LoadServices()
	if err != nil {
		return nil, fmt.Errorf("error loading services: %v", err)
	}

	return dataManager, nil
}

func checkServiceRegManagerConfig(config *RemoteServiceRegManagerConfig, firstParty bool) error {
	if config.ServiceRegHost == "" {
		return errors.New("service registration host is missing")
	}
	if config.ServiceID == "" {
		return errors.New("service ID is missing")
	}

	if config.Path == "" {
		if firstParty {
			config.Path = "bbs/service-regs"
		} else {
			config.Path = "tps/service-regs"
		}
	}

	if config.MinRefreshCacheFreq == 0 {
		config.MinRefreshCacheFreq = 1
	}
	if config.MaxRefreshCacheFreq == 0 || config.MaxRefreshCacheFreq < config.MinRefreshCacheFreq {
		config.MaxRefreshCacheFreq = 60
	}

	return nil
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

// -------------------- AccessToken --------------------

// AccessToken represents an access token granted by a remote service account host
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
