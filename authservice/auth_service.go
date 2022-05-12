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
	"bytes"
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

const (
	allID string = "all"
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
	if freq >= s.minRefreshCacheFreq {
		s.maxRefreshCacheFreq = freq
	}
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
	GetAccessToken(appID string, orgID string) error
	// GetAccessTokens get an access token for each app org pair a service account is granted access
	GetAccessTokens() error
	// CachedAccessToken returns a cached token
	CachedAccessToken() AccessToken
}

//RemoteServiceAccountManagerImpl provides a ServiceAccountManager implementation for a remote auth service
type RemoteServiceAccountManagerImpl struct {
	AuthService *AuthService

	accessTokens *syncmap.Map
	appOrgPairs  []AppOrgPair

	tokensLock          *sync.RWMutex
	tokensUpdated       *time.Time
	maxRefreshCacheFreq uint

	accessTokenPath  string // Path to service account access token API
	accessTokensPath string // Path to service account access tokens API

	config RemoteServiceAccountManagerConfig
}

// GetAccessToken implements ServiceAccountManager interface
func (r *RemoteServiceAccountManagerImpl) GetAccessToken(appID string, orgID string) error {
	req, err := r.buildAccessTokenRequest(appID, orgID)
	if err != nil {
		return fmt.Errorf("error creating access token request: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending access token request: %v", err)
	}
	body, err := r.ReadResponse(resp)
	if err != nil {
		return fmt.Errorf("error reading access token response: %v", err)
	}

	var accessToken AccessToken
	err = json.Unmarshal(body, &accessToken)
	if err != nil {
		return fmt.Errorf("error on unmarshal access token response: %v", err)
	}

	r.accessTokens.Store(AppOrgPair{AppID: appID, OrgID: orgID}, accessToken)

	return nil
}

// GetAccessTokens implements ServiceAccountManager interface
func (r *RemoteServiceAccountManagerImpl) GetAccessTokens() error {
	req, err := r.buildAccessTokensRequest()
	if err != nil {
		return fmt.Errorf("error creating access tokens request: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending access tokens request: %v", err)
	}
	body, err := r.ReadResponse(resp)
	if err != nil {
		return fmt.Errorf("error reading access tokens response: %v", err)
	}

	var accessTokens []accessTokensResponse
	err = json.Unmarshal(body, &accessTokens)
	if err != nil {
		return fmt.Errorf("error on unmarshal access tokens response: %v", err)
	}

	// update caches
	r.accessTokens = &sync.Map{}
	r.tokensLock.Lock()
	defer r.tokensLock.Unlock()

	r.appOrgPairs = make([]AppOrgPair, len(accessTokens))
	for i, res := range accessTokens {
		pair := AppOrgPair{AppID: res.AppID, OrgID: res.OrgID}

		r.appOrgPairs[i] = pair
		r.accessTokens.Store(pair, res.AccessToken)
	}

	now := time.Now()
	r.tokensUpdated = &now

	return nil
}

// MakeRequest makes the provided http.Request with the token granting appropriate access to appID and orgID
func (r *RemoteServiceAccountManagerImpl) MakeRequest(req *http.Request, appID string, orgID string) (*http.Response, error) {
	token, appOrgPair := r.getCachedAccessToken(appID, orgID)
	if token == nil || appOrgPair == nil {
		// check if tokens should be refreshed and get the new token if so
		refreshed, err := r.checkForRefresh()
		if err != nil {
			return nil, fmt.Errorf("error checking access tokens refresh: %v", err)
		}
		if !refreshed {
			return nil, fmt.Errorf("access not granted for appID %s, orgID %s", appID, orgID)
		}

		token, appOrgPair = r.getCachedAccessToken(appID, orgID)
		if token == nil || appOrgPair == nil {
			return nil, fmt.Errorf("access not granted for appID %s, orgID %s", appID, orgID)
		}
	}

	req.Header.Set("Authorization", (*token).String())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		// access token may have expired, so get new ones and try once more
		updateErr := r.GetAccessTokens()
		if updateErr != nil {
			return nil, fmt.Errorf("error getting new access tokens (%s) - after %v", updateErr, err)
		}

		token, appOrgPair = r.getCachedAccessToken(appOrgPair.AppID, appOrgPair.OrgID)
		if token == nil || appOrgPair == nil {
			return nil, fmt.Errorf("access not granted for appID %s, orgID %s", appID, orgID)
		}

		resp, err = client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("error sending request: %v", err)
		}
	}

	return resp, nil
}

// CachedAccessTokens returns a map containing all cached access tokens
func (r *RemoteServiceAccountManagerImpl) CachedAccessTokens() map[AppOrgPair]AccessToken {
	tokens := make(map[AppOrgPair]AccessToken)
	r.accessTokens.Range(func(key, item interface{}) bool {
		keyPair, ok := key.(AppOrgPair)
		if !ok {
			return false
		}

		if item == nil {
			return false
		} else if accessToken, ok := item.(AccessToken); !ok {
			return false
		} else {
			tokens[keyPair] = accessToken
			return true
		}
	})

	return tokens
}

// CachedAppOrgPairs returns the list of cached app org pairs
func (r *RemoteServiceAccountManagerImpl) CachedAppOrgPairs() []AppOrgPair {
	return r.appOrgPairs
}

// ReadResponse reads the body of a http.Response and returns it
func (r *RemoteServiceAccountManagerImpl) ReadResponse(resp *http.Response) ([]byte, error) {
	if resp == nil {
		return nil, errors.New("response is nil")
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	if resp.StatusCode != 200 {
		return body, fmt.Errorf("%s - %s", resp.Status, string(body))
	}

	return body, nil
}

// SetMaxRefreshCacheFreq sets the maximum frequency at which cached access tokens are refreshed in minutes
// 	The default value is 30
func (r *RemoteServiceAccountManagerImpl) SetMaxRefreshCacheFreq(freq uint) {
	r.tokensLock.Lock()
	r.maxRefreshCacheFreq = freq
	r.tokensLock.Unlock()
}

//checkForRefresh checks if access tokens need to be reloaded
func (r *RemoteServiceAccountManagerImpl) checkForRefresh() (bool, error) {
	r.tokensLock.RLock()
	tokensUpdated := r.tokensUpdated
	maxRefreshFreq := r.maxRefreshCacheFreq
	r.tokensLock.RUnlock()

	now := time.Now()
	if tokensUpdated == nil || now.Sub(*tokensUpdated).Minutes() > float64(maxRefreshFreq) {
		err := r.GetAccessTokens()
		if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// getCachedAccessToken returns the most restrictive cached token (with corresponding pair) granting access to appID and orgID, if it exists
func (r *RemoteServiceAccountManagerImpl) getCachedAccessToken(appID string, orgID string) (*AccessToken, *AppOrgPair) {
	allowedPairs := []AppOrgPair{{AppID: appID, OrgID: orgID}}
	if appID != allID || orgID != allID {
		if appID != allID && orgID != allID {
			allowedPairs = append(allowedPairs, AppOrgPair{AppID: allID, OrgID: orgID})
			allowedPairs = append(allowedPairs, AppOrgPair{AppID: appID, OrgID: allID})
		}

		allowedPairs = append(allowedPairs, AppOrgPair{AppID: allID, OrgID: allID})
	}

	for _, allowed := range allowedPairs {
		for _, cached := range r.appOrgPairs {
			if cached.Equals(allowed) {
				if item, found := r.accessTokens.Load(allowed); found && item != nil {
					if token, ok := item.(AccessToken); ok {
						return &token, &allowed
					}
				}
				return nil, nil
			}
		}
	}

	return nil, nil
}

//RemoteServiceAccountManagerConfig represents a configuration for a remote service account manager
type RemoteServiceAccountManagerConfig struct {
	AccountID string // Service account ID on the auth service

	ServiceAuthRequests ServiceAuthRequests
}

// buildAccessTokenRequest returns a HTTP request to get a single access token
func (r *RemoteServiceAccountManagerImpl) buildAccessTokenRequest(appID string, orgID string) (*http.Request, error) {
	body := r.config.ServiceAuthRequests.BuildRequestAuthBody()
	body["account_id"] = r.config.AccountID
	body["app_id"] = appID
	body["org_id"] = orgID

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request body to get access token: %v", err)
	}

	req, err := http.NewRequest("POST", r.AuthService.AuthBaseURL+r.accessTokenPath, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("error formatting request to get access token: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	err = r.config.ServiceAuthRequests.ModifyRequest(req)
	if err != nil {
		return nil, fmt.Errorf("error modifying request to get access token: %v", err)
	}

	return req, nil
}

// buildAccessTokensRequest returns a HTTP request to get all allowed access tokens
func (r *RemoteServiceAccountManagerImpl) buildAccessTokensRequest() (*http.Request, error) {
	body := r.config.ServiceAuthRequests.BuildRequestAuthBody()
	body["account_id"] = r.config.AccountID

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request body to get access tokens: %v", err)
	}

	req, err := http.NewRequest("POST", r.AuthService.AuthBaseURL+r.accessTokensPath, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("error formatting request to get access tokens: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	err = r.config.ServiceAuthRequests.ModifyRequest(req)
	if err != nil {
		return nil, fmt.Errorf("error modifying request to get access token: %v", err)
	}

	return req, nil
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
	accessTokensPath := "tps/access-tokens"
	if authService.FirstParty {
		accessTokenPath = "bbs/access-token"
		accessTokensPath = "bbs/access-tokens"
	}

	accessTokens := &syncmap.Map{}

	appOrgPairs := make([]AppOrgPair, 0)
	lock := &sync.RWMutex{}

	dataManager := RemoteServiceAccountManagerImpl{AuthService: authService, accessTokens: accessTokens, appOrgPairs: appOrgPairs,
		tokensLock: lock, maxRefreshCacheFreq: 30, accessTokenPath: accessTokenPath, accessTokensPath: accessTokensPath, config: config}
	return &dataManager, nil
}

func checkServiceAccountManagerConfig(config *RemoteServiceAccountManagerConfig) error {
	if config.AccountID == "" {
		return errors.New("service account ID is missing")
	}

	if config.ServiceAuthRequests == nil {
		return fmt.Errorf("service auth requests not set")
	}

	return nil
}

// -------------------- ServiceAuthRequests --------------------

// ServiceAuthRequests declares an interface for setting up HTTP requests to APIs requiring certain types of authentication
type ServiceAuthRequests interface {
	BuildRequestAuthBody() map[string]interface{} // Construct auth fields for service account request bodies
	ModifyRequest(req *http.Request) error        // Performs any auth type specific modifications to the request and returns any errors that occur
}

// StaticTokenServiceAuth provides a ServiceAuthRequests implementation for static token-based auth
type StaticTokenServiceAuth struct {
	ServiceToken string // Static token issued by the auth service, used to get access tokens from the auth service
}

// BuildRequestAuthBody returns a map containing the auth fields for static token auth request bodies
func (s StaticTokenServiceAuth) BuildRequestAuthBody() map[string]interface{} {
	return map[string]interface{}{
		"auth_type": "static_token",
		"creds": map[string]string{
			"token": s.ServiceToken,
		},
	}
}

// ModifyRequest leaves the passed request unmodified for static token auth
func (s StaticTokenServiceAuth) ModifyRequest(req *http.Request) error {
	return nil
}

// -------------------- AppOrgPair --------------------

// AppOrgPair represents application organization pair access granted by a remote auth service
type AppOrgPair struct {
	AppID string
	OrgID string
}

// Equals checks if two AppOrgPairs are equivalent
func (ao AppOrgPair) Equals(other AppOrgPair) bool {
	return ao.AppID == other.AppID && ao.OrgID == other.OrgID
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

type accessTokensResponse struct {
	AppID       string      `json:"app_id"`
	OrgID       string      `json:"org_id"`
	AccessToken AccessToken `json:"token"`
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
