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
	"context"
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
	// AllID represents all possible options for an ID
	AllID string = "all"
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

// ServiceRegManager declares a type used to manage service registrations
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
	client      *http.Client

	path string // Path to service registrations resource on the auth service

	*ServiceRegSubscriptions
}

// LoadServices implements ServiceRegLoader interface
func (r *RemoteServiceRegLoaderImpl) LoadServices() ([]ServiceReg, error) {
	if len(r.GetSubscribedServices()) == 0 {
		return nil, nil
	}

	req, err := http.NewRequest("GET", r.authService.AuthBaseURL+r.path, nil)
	if err != nil {
		return nil, fmt.Errorf("error formatting request to load services: %v", err)
	}

	servicesQuery := strings.Join(r.GetSubscribedServices(), ",")

	q := req.URL.Query()
	q.Add("ids", servicesQuery)
	req.URL.RawQuery = q.Encode()

	resp, err := r.client.Do(req)
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

	path := "/tps/service-regs"
	if authService.FirstParty {
		path = "/bbs/service-regs"
	}

	subscriptions := NewServiceRegSubscriptions(subscribedServices)
	return &RemoteServiceRegLoaderImpl{authService: authService, client: &http.Client{}, path: path, ServiceRegSubscriptions: subscriptions}, nil
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

// ServiceAccountManager declares a type used to manage service account data
type ServiceAccountManager struct {
	AuthService *AuthService

	accessTokens *syncmap.Map
	appOrgPairs  []AppOrgPair

	tokensLock          *sync.RWMutex
	tokensUpdated       *time.Time
	maxRefreshCacheFreq uint

	client *http.Client

	loader ServiceAccountLoader
}

// GetAccessToken attempts to load an access token for appID and orgID, then caches it if successful
func (s *ServiceAccountManager) GetAccessToken(appID string, orgID string) (*AccessToken, error) {
	token, err := s.loader.LoadAccessToken(appID, orgID)
	if err != nil {
		return nil, fmt.Errorf("error loading access token: %v", err)
	}

	s.accessTokens.Store(AppOrgPair{AppID: appID, OrgID: orgID}, *token)
	return token, nil
}

// GetAccessTokens attempts to get all allowed access tokens for the implementing service, then caches them if successful
func (s *ServiceAccountManager) GetAccessTokens() (map[AppOrgPair]AccessToken, []AppOrgPair, error) {
	tokens, err := s.loader.LoadAccessTokens()
	if err != nil {
		return nil, nil, fmt.Errorf("error loading access tokens: %v", err)
	}

	// update caches
	s.accessTokens = &sync.Map{}

	oldPairs := make([]string, len(s.appOrgPairs))
	newPairs := make([]AppOrgPair, 0)
	for i, pair := range s.appOrgPairs {
		oldPairs[i] = pair.String()
	}

	i := 0
	s.appOrgPairs = make([]AppOrgPair, len(tokens))
	for pair, token := range tokens {
		s.appOrgPairs[i] = pair
		if !authutils.ContainsString(oldPairs, pair.String()) {
			oldPairs = append(oldPairs, pair.String()) // filters out any duplicate new pairs
			newPairs = append(newPairs, pair)
		}

		s.accessTokens.Store(pair, token)
		i++
	}

	now := time.Now()
	s.tokensUpdated = &now

	return tokens, newPairs, nil
}

// MakeRequest makes the provided http.Request with the token granting appropriate access to appID and orgID
func (s *ServiceAccountManager) MakeRequest(req *http.Request, appID string, orgID string) (*http.Response, error) {
	return s.makeRequest(req, appID, orgID, nil, nil, nil)
}

// MakeRequests makes the provided http.Request using tokens granting access to each AppOrgPair
func (s *ServiceAccountManager) MakeRequests(req *http.Request, pairs []AppOrgPair) map[AppOrgPair]RequestResponse {
	responsesChan := make(chan map[AppOrgPair]RequestResponse, 2)
	responses := make(map[AppOrgPair]RequestResponse)

	// use WaitGroup to ensure all responses are collected (makeRequests may launch a single makeRequests goroutine if new pairs are discovered)
	var wg sync.WaitGroup
	wg.Add(1)
	go s.makeRequests(req, pairs, responsesChan, &wg)
	wg.Wait()

	close(responsesChan)
	for responseMap := range responsesChan {
		for pair, res := range responseMap {
			responses[pair] = res
		}
	}

	return responses
}

// AccessTokens returns a map containing all cached access tokens
func (s *ServiceAccountManager) AccessTokens() map[AppOrgPair]AccessToken {
	tokens := make(map[AppOrgPair]AccessToken)
	s.accessTokens.Range(func(key, item interface{}) bool {
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

// AppOrgPairs returns the list of cached app org pairs
func (s *ServiceAccountManager) AppOrgPairs() []AppOrgPair {
	return s.appOrgPairs
}

// SetMaxRefreshCacheFreq sets the maximum frequency at which cached access tokens are refreshed in minutes
// 	The default value is 30
func (s *ServiceAccountManager) SetMaxRefreshCacheFreq(freq uint) {
	s.tokensLock.Lock()
	s.maxRefreshCacheFreq = freq
	s.tokensLock.Unlock()
}

// getCachedAccessToken returns the most restrictive cached token (with corresponding pair) granting access to appID and orgID, if it exists
func (s *ServiceAccountManager) getCachedAccessToken(appID string, orgID string) (*AccessToken, *AppOrgPair) {
	allowedPairs := []AppOrgPair{{AppID: appID, OrgID: orgID}}
	if appID != AllID || orgID != AllID {
		if appID != AllID && orgID != AllID {
			allowedPairs = append(allowedPairs, AppOrgPair{AppID: AllID, OrgID: orgID})
			allowedPairs = append(allowedPairs, AppOrgPair{AppID: appID, OrgID: AllID})
		}

		allowedPairs = append(allowedPairs, AppOrgPair{AppID: AllID, OrgID: AllID})
	}

	for _, allowed := range allowedPairs {
		for _, cached := range s.appOrgPairs {
			if cached.Equals(allowed) {
				if item, found := s.accessTokens.Load(allowed); found && item != nil {
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

// checkForRefresh checks if access tokens need to be reloaded
func (s *ServiceAccountManager) checkForRefresh() ([]AppOrgPair, error) {
	s.tokensLock.Lock()
	defer s.tokensLock.Unlock()
	tokensUpdated := s.tokensUpdated
	maxRefreshFreq := s.maxRefreshCacheFreq

	var newPairs []AppOrgPair
	var err error
	now := time.Now()
	if tokensUpdated == nil || now.Sub(*tokensUpdated).Minutes() > float64(maxRefreshFreq) {
		_, newPairs, err = s.GetAccessTokens()
		if err != nil {
			return nil, err
		}
	}

	return newPairs, nil
}

// getRefreshedAccessToken checks if tokens should be refreshed and gets a new token for appID, orgID if so
func (s *ServiceAccountManager) getRefreshedAccessToken(appID string, orgID string) (*AccessToken, *AppOrgPair, []AppOrgPair, error) {
	newPairs, err := s.checkForRefresh()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error checking access tokens refresh: %v", err)
	}

	refreshedToken, refreshedPair := s.getCachedAccessToken(appID, orgID)
	if refreshedToken == nil || refreshedPair == nil {
		return nil, nil, newPairs, fmt.Errorf("access not granted for appID %s, orgID %s", appID, orgID)
	}

	return refreshedToken, refreshedPair, newPairs, nil
}

// makeRequest sends a HTTP request with a token granting access to appID, orgID
func (s *ServiceAccountManager) makeRequest(req *http.Request, appID string, orgID string, rrc chan<- RequestResponse, pc chan<- []AppOrgPair, dc <-chan bool) (*http.Response, error) {
	async := (rrc != nil) && (pc != nil) && (dc != nil)
	var err error

	token, appOrgPair := s.getCachedAccessToken(appID, orgID)
	if token == nil || appOrgPair == nil {
		// the requested pair is missing from the cache, so try refreshing tokens to find the missing one
		token, appOrgPair, _, err = s.getRefreshedAccessToken(appID, orgID)
		if err != nil {
			return s.handleRequestResponse(async, true, AppOrgPair{AppID: appID, OrgID: orgID}, nil, err, nil, rrc, pc, dc)
		}
	}

	if async {
		pc <- []AppOrgPair{*appOrgPair, {AppID: appID, OrgID: orgID}}
		if <-dc {
			return s.handleRequestResponse(async, false, *appOrgPair, nil, nil, nil, rrc, pc, dc)
		}
	}

	req.Header.Set("Authorization", token.String())
	resp, err := s.client.Do(req)
	if err != nil {
		retErr := fmt.Errorf("error sending request: %v", err)
		return s.handleRequestResponse(async, false, *appOrgPair, nil, retErr, nil, rrc, pc, dc)
	}

	var newPairs []AppOrgPair
	if resp.StatusCode == http.StatusUnauthorized {
		// unauthorized, so try refreshing tokens and try once more with a refreshed token
		var refreshedPair *AppOrgPair
		token, refreshedPair, newPairs, err = s.getRefreshedAccessToken(appOrgPair.AppID, appOrgPair.OrgID)
		if err != nil {
			return s.handleRequestResponse(async, false, *appOrgPair, nil, err, newPairs, rrc, pc, dc)
		}

		req.Header.Set("Authorization", token.String())
		resp, err = s.client.Do(req)
		if err != nil {
			retErr := fmt.Errorf("error sending request: %v", err)
			return s.handleRequestResponse(async, false, *refreshedPair, nil, retErr, newPairs, rrc, pc, dc)
		}

		appOrgPair = refreshedPair
	}

	return s.handleRequestResponse(async, false, *appOrgPair, resp, nil, newPairs, rrc, pc, dc)
}

// handleRequestResponse sends and receives data on the given channels if used in an asynchronous call to makeRequest
func (s *ServiceAccountManager) handleRequestResponse(async bool, allStage bool, tokenPair AppOrgPair, resp *http.Response, err error, newPairs []AppOrgPair,
	rrc chan<- RequestResponse, pc chan<- []AppOrgPair, dc <-chan bool) (*http.Response, error) {
	if async {
		if allStage {
			pc <- []AppOrgPair{{AppID: tokenPair.AppID, OrgID: tokenPair.OrgID}, {AppID: tokenPair.AppID, OrgID: tokenPair.OrgID}}
			<-dc
		}

		rrc <- RequestResponse{TokenPair: tokenPair, Response: resp, Error: err}
		pc <- newPairs
	}

	return resp, err
}

// makeRequests sends a HTTP request for each AppOrgPair in the given list, or all cached pairs if nil
func (s *ServiceAccountManager) makeRequests(req *http.Request, pairs []AppOrgPair, rc chan map[AppOrgPair]RequestResponse, wg *sync.WaitGroup) {
	defer wg.Done()

	responseChan := make(chan RequestResponse)
	pairChan := make(chan []AppOrgPair)
	duplicateChan := make(chan bool)

	responses := make(map[AppOrgPair]RequestResponse)
	tokenPairs := make(map[AppOrgPair][]AppOrgPair)
	uniquePairs := make([]string, 0)

	useCachedPairs := pairs == nil
	if useCachedPairs {
		pairs = s.appOrgPairs
	}

	// filter out duplicate pairs and launch a goroutine for each unique requested pair
	for _, pair := range pairs {
		if !authutils.ContainsString(uniquePairs, pair.String()) {
			uniquePairs = append(uniquePairs, pair.String())
			go s.makeRequest(req.Clone(context.Background()), pair.AppID, pair.OrgID, responseChan, pairChan, duplicateChan)
		}
	}

	// store mapping of token pairs used for each unique requested pair, and signal each goroutine whether another goroutine is using its token pair
	// token pairs are the pairs that correspond to the token each goroutine attempts to use in the given request
	for range uniquePairs {
		pairs := <-pairChan
		tokenPair := pairs[0]
		argPair := pairs[1]

		if len(tokenPairs[tokenPair]) == 0 {
			tokenPairs[tokenPair] = []AppOrgPair{argPair}
			duplicateChan <- false
		} else {
			tokenPairs[tokenPair] = append(tokenPairs[tokenPair], argPair)
			duplicateChan <- true
		}
	}

	// receive a response from each goroutine (one response for each unique token pair)
	// if new pairs are discovered (i.e., during a token refresh), send requests for these if cached pairs are being used to send requests
	for range uniquePairs {
		requestResp := <-responseChan
		if !requestResp.IsZero() {
			requestResp.Pairs = tokenPairs[requestResp.TokenPair]
			responses[requestResp.TokenPair] = requestResp
		}

		newPairs := <-pairChan
		if len(newPairs) > 0 && useCachedPairs {
			wg.Add(1)
			go s.makeRequests(req, newPairs, rc, wg)
		}
	}

	// cleanup and send responses
	close(responseChan)
	close(pairChan)
	close(duplicateChan)

	rc <- responses
}

// NewServiceAccountManager creates and configures a new ServiceAccountManager instance
func NewServiceAccountManager(authService *AuthService, serviceAccountLoader ServiceAccountLoader) (*ServiceAccountManager, error) {
	err := checkAuthService(authService, false)
	if err != nil {
		return nil, fmt.Errorf("error checking auth service: %v", err)
	}

	if serviceAccountLoader == nil {
		return nil, errors.New("service account loader is missing")
	}

	accessTokens := &syncmap.Map{}

	appOrgPairs := make([]AppOrgPair, 0)
	lock := &sync.RWMutex{}

	manager := &ServiceAccountManager{AuthService: authService, accessTokens: accessTokens, appOrgPairs: appOrgPairs,
		tokensLock: lock, maxRefreshCacheFreq: 30, client: &http.Client{}, loader: serviceAccountLoader}

	// Subscribe to the implementing service to validate registration
	_, _, err = manager.GetAccessTokens()
	if err != nil {
		return nil, fmt.Errorf("error loading access tokens: %v", err)
	}

	return manager, nil
}

// -------------------- ServiceAccountLoader --------------------

// ServiceAccountLoader declares an interface to load service account-related data from an auth service
type ServiceAccountLoader interface {
	// LoadAccessToken gets an access token for appID, orgID if the implementing service is granted access
	LoadAccessToken(appID string, orgID string) (*AccessToken, error)
	// LoadAccessToken gets an access token for each app org pair the implementing service is granted access
	LoadAccessTokens() (map[AppOrgPair]AccessToken, error)
}

//RemoteServiceAccountLoaderImpl provides a ServiceAccountLoader implementation for a remote auth service
type RemoteServiceAccountLoaderImpl struct {
	authService *AuthService
	client      *http.Client

	accountID string // Service account ID on the auth service

	accessTokenPath  string // Path to service account access token API
	accessTokensPath string // Path to service account access tokens API

	serviceAuthType ServiceAuthType // auth type used by ServiceAccountLoader requests to the auth service
}

// LoadAccessToken implements ServiceAccountLoader interface
func (r *RemoteServiceAccountLoaderImpl) LoadAccessToken(appID string, orgID string) (*AccessToken, error) {
	req, err := r.buildAccessTokenRequest(appID, orgID)
	if err != nil {
		return nil, fmt.Errorf("error creating access token request: %v", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending access token request: %v", err)
	}
	body, err := authutils.ReadResponseBody(resp)
	if err != nil {
		return nil, fmt.Errorf("error reading access token response: %v", err)
	}

	var token AccessToken
	err = json.Unmarshal(body, &token)
	if err != nil {
		return nil, fmt.Errorf("error on unmarshal access token response: %v", err)
	}

	return &token, nil
}

// LoadAccessTokens implements ServiceAccountLoader interface
func (r *RemoteServiceAccountLoaderImpl) LoadAccessTokens() (map[AppOrgPair]AccessToken, error) {
	req, err := r.buildAccessTokensRequest()
	if err != nil {
		return nil, fmt.Errorf("error creating access tokens request: %v", err)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending access tokens request: %v", err)
	}
	body, err := authutils.ReadResponseBody(resp)
	if err != nil {
		return nil, fmt.Errorf("error reading access tokens response: %v", err)
	}

	var tokens []accessTokensResponse
	err = json.Unmarshal(body, &tokens)
	if err != nil {
		return nil, fmt.Errorf("error on unmarshal access tokens response: %v", err)
	}

	tokenMap := make(map[AppOrgPair]AccessToken)
	for _, res := range tokens {
		pair := AppOrgPair{AppID: res.AppID, OrgID: res.OrgID}
		tokenMap[pair] = res.AccessToken
	}

	return tokenMap, nil
}

// buildAccessTokenRequest returns a HTTP request to get a single access token
func (r *RemoteServiceAccountLoaderImpl) buildAccessTokenRequest(appID string, orgID string) (*http.Request, error) {
	body := r.serviceAuthType.BuildRequestAuthBody()
	body["account_id"] = r.accountID
	body["app_id"] = appID
	body["org_id"] = orgID

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request body to get access token: %v", err)
	}

	req, err := http.NewRequest("POST", r.authService.AuthBaseURL+r.accessTokenPath, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("error formatting request to get access token: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	err = r.serviceAuthType.ModifyRequest(req)
	if err != nil {
		return nil, fmt.Errorf("error modifying request to get access token: %v", err)
	}

	return req, nil
}

// buildAccessTokensRequest returns a HTTP request to get all allowed access tokens
func (r *RemoteServiceAccountLoaderImpl) buildAccessTokensRequest() (*http.Request, error) {
	body := r.serviceAuthType.BuildRequestAuthBody()
	body["account_id"] = r.accountID

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request body to get access tokens: %v", err)
	}

	req, err := http.NewRequest("POST", r.authService.AuthBaseURL+r.accessTokensPath, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("error formatting request to get access tokens: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	err = r.serviceAuthType.ModifyRequest(req)
	if err != nil {
		return nil, fmt.Errorf("error modifying request to get access token: %v", err)
	}

	return req, nil
}

// NewRemoteServiceAccountLoader creates and configures a new RemoteServiceAccountLoaderImpl instance
func NewRemoteServiceAccountLoader(authService *AuthService, accountID string, serviceAuthType ServiceAuthType) (*RemoteServiceAccountLoaderImpl, error) {
	err := checkAuthService(authService, true)
	if err != nil {
		return nil, fmt.Errorf("error checking auth service: %v", err)
	}

	if accountID == "" {
		return nil, errors.New("account ID is missing")
	}
	if serviceAuthType == nil {
		return nil, fmt.Errorf("service auth requests are not set")
	}

	accessTokenPath := "/tps/access-token"
	accessTokensPath := "/tps/access-tokens"
	if authService.FirstParty {
		accessTokenPath = "/bbs/access-token"
		accessTokensPath = "/bbs/access-tokens"
	}

	return &RemoteServiceAccountLoaderImpl{authService: authService, client: &http.Client{}, accountID: accountID, accessTokenPath: accessTokenPath,
		accessTokensPath: accessTokensPath, serviceAuthType: serviceAuthType}, nil
}

// -------------------- ServiceAuthRequests --------------------

// ServiceAuthType declares an interface for setting up HTTP requests to APIs requiring certain types of authentication
type ServiceAuthType interface {
	// Construct auth fields for service account request bodies
	BuildRequestAuthBody() map[string]interface{}
	// Performs any auth type specific modifications to the request and returns any errors that occur
	ModifyRequest(req *http.Request) error
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

// String returns the app org pair as a string
func (ao AppOrgPair) String() string {
	if ao.AppID == "" || ao.OrgID == "" {
		return ""
	}
	return fmt.Sprintf("%s_%s", ao.AppID, ao.OrgID)
}

// -------------------- AccessToken --------------------

// AccessToken represents an access token granted by a remote auth service
type AccessToken struct {
	Token     string `json:"access_token"`
	TokenType string `json:"token_type"`
}

// String returns the access token as a string
func (t AccessToken) String() string {
	if t.Token == "" {
		return ""
	}
	return fmt.Sprintf("%s %s", t.TokenType, t.Token)
}

type accessTokensResponse struct {
	AppID       string      `json:"app_id"`
	OrgID       string      `json:"org_id"`
	AccessToken AccessToken `json:"token"`
}

// -------------------- RequestResponse --------------------

// RequestResponse represents a response to a unique MakeRequest call
type RequestResponse struct {
	Pairs     []AppOrgPair
	TokenPair AppOrgPair
	Response  *http.Response
	Error     error
}

// IsZero determines if the RequestResponse object has its zero value
func (rr RequestResponse) IsZero() bool {
	return rr.Pairs == nil && len(rr.TokenPair.String()) == 0 && rr.Response == nil && rr.Error == nil
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
