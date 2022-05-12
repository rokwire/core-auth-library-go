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
	"github.com/rokwire/logging-library-go/logs"
	"golang.org/x/sync/syncmap"
	"gopkg.in/go-playground/validator.v9"
)

const (
	allID string = "all"
)

// -------------------- AuthService --------------------

// AuthService contains the configurations to interface with the auth service
type AuthService struct {
	dataLoader AuthDataLoader

	// ID of implementing service
	serviceID string

	services        *syncmap.Map
	servicesUpdated *time.Time
	servicesLock    *sync.RWMutex

	minRefreshCacheFreq int
	maxRefreshCacheFreq int
}

// GetServiceID returns the ID of the implementing service
func (a *AuthService) GetServiceID() string {
	return a.serviceID
}

// GetServiceReg returns the service registration record for the given ID if found
func (a *AuthService) GetServiceReg(id string) (*ServiceReg, error) {
	a.servicesLock.RLock()
	servicesUpdated := a.servicesUpdated
	maxRefreshFreq := a.maxRefreshCacheFreq
	a.servicesLock.RUnlock()

	var loadServicesError error
	now := time.Now()
	if servicesUpdated == nil || now.Sub(*servicesUpdated).Minutes() > float64(maxRefreshFreq) {
		loadServicesError = a.LoadServices()
	}

	var service ServiceReg

	if a.services == nil {
		return nil, fmt.Errorf("services could not be loaded: %v", loadServicesError)
	}
	itemValue, ok := a.services.Load(id)
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
func (a *AuthService) GetServiceRegWithPubKey(id string) (*ServiceReg, error) {
	serviceReg, err := a.GetServiceReg(id)
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
func (a *AuthService) LoadServices() error {
	services, loadServicesError := a.dataLoader.LoadServices()
	if services != nil {
		a.setServices(services)
	}
	return loadServicesError
}

// SubscribeServices subscribes to the provided services
//	If reload is true and one of the services is not already subscribed, the service registrations will be reloaded immediately
func (a *AuthService) SubscribeServices(serviceIDs []string, reload bool) error {
	newSub := false

	for _, serviceID := range serviceIDs {
		subscribed := a.dataLoader.SubscribeService(serviceID)
		if subscribed {
			newSub = true
		}
	}

	if reload && newSub {
		err := a.LoadServices()
		if err != nil {
			return fmt.Errorf("error loading service registrations: %v", err)
		}
	}

	return nil
}

// UnsubscribeServices unsubscribes from the provided service
func (a *AuthService) UnsubscribeServices(serviceIDs []string) {
	for _, serviceID := range serviceIDs {
		a.dataLoader.UnsubscribeService(serviceID)
	}
}

// ValidateServiceRegistration validates that the implementing service has a valid registration for the provided service ID and hostname
func (a *AuthService) ValidateServiceRegistration(serviceHost string) error {
	service, err := a.GetServiceReg(a.serviceID)
	if err != nil || service == nil {
		return fmt.Errorf("no service registration found with id %s: %v", a.serviceID, err)
	}

	if serviceHost != service.Host {
		return fmt.Errorf("service host (%s) does not match expected value (%s) for id %s", service.Host, serviceHost, a.serviceID)
	}

	return nil
}

// ValidateServiceRegistrationKey validates that the implementing service has a valid registration for the provided keypair
func (a *AuthService) ValidateServiceRegistrationKey(privKey *rsa.PrivateKey) error {
	if privKey == nil {
		return errors.New("provided priv key is nil")
	}

	service, err := a.GetServiceRegWithPubKey(a.serviceID)
	if err != nil {
		return fmt.Errorf("failed to retrieve service pub key: %v", err)
	}

	if service.PubKey.Key.Equal(privKey.PublicKey) {
		return fmt.Errorf("service pub key does not match for id %s", a.serviceID)
	}

	return nil
}

// SetMinRefreshCacheFreq sets the minimum frequency at which cached service registration records are refreshed in minutes
// 	The default value is 1
func (a *AuthService) SetMinRefreshCacheFreq(freq int) {
	a.servicesLock.Lock()
	a.minRefreshCacheFreq = freq
	a.servicesLock.Unlock()
}

// SetMaxRefreshCacheFreq sets the minimum frequency at which cached service registration records are refreshed in minutes
// 	The default value is 60
func (a *AuthService) SetMaxRefreshCacheFreq(freq int) {
	a.servicesLock.Lock()
	a.maxRefreshCacheFreq = freq
	a.servicesLock.Unlock()
}

func (a *AuthService) setServices(services []ServiceReg) {
	a.servicesLock.Lock()

	a.services = &syncmap.Map{}
	if len(services) > 0 {
		for _, service := range services {
			a.services.Store(service.ServiceID, service)
			a.services.Store(service.ServiceAccountID, service)
		}
	}

	time := time.Now()
	a.servicesUpdated = &time

	a.servicesLock.Unlock()
}

// NewAuthService creates and configures a new AuthService instance
func NewAuthService(serviceID string, serviceHost string, dataLoader AuthDataLoader) (*AuthService, error) {
	if dataLoader == nil {
		return nil, errors.New("data loader is missing")
	}

	// Subscribe to the implementing service to validate registration
	dataLoader.SubscribeService(serviceID)

	lock := &sync.RWMutex{}
	services := &syncmap.Map{}

	auth := &AuthService{dataLoader: dataLoader, serviceID: serviceID, services: services, servicesLock: lock,
		minRefreshCacheFreq: 1, maxRefreshCacheFreq: 60}

	err := auth.LoadServices()
	if err != nil {
		return nil, fmt.Errorf("error loading services: %v", err)
	}

	err = auth.ValidateServiceRegistration(serviceHost)
	if err != nil {
		return nil, fmt.Errorf("unable to validate service registration: please contact the auth service system admin to register your service - %v", err)
	}

	return auth, nil
}

//CheckForRefresh checks if service registrations need to be reloaded
func (a *AuthService) CheckForRefresh() (bool, error) {
	a.servicesLock.RLock()
	servicesUpdated := a.servicesUpdated
	minRefreshFreq := a.minRefreshCacheFreq
	a.servicesLock.RUnlock()

	var loadServicesError error
	now := time.Now()
	if servicesUpdated == nil || now.Sub(*servicesUpdated).Minutes() > float64(minRefreshFreq) {
		loadServicesError = a.LoadServices()
		return true, loadServicesError
	}
	return false, loadServicesError
}

// NewTestAuthService creates and configures a new AuthService instance for testing purposes
func NewTestAuthService(serviceID string, serviceHost string, dataLoader AuthDataLoader) (*AuthService, error) {
	// Subscribe to the implementing service to validate registration
	dataLoader.SubscribeService(serviceID)

	lock := &sync.RWMutex{}
	services := &syncmap.Map{}

	auth := &AuthService{dataLoader: dataLoader, serviceID: serviceID, services: services, servicesLock: lock,
		minRefreshCacheFreq: 1, maxRefreshCacheFreq: 60}
	err := auth.LoadServices()
	if err != nil {
		return nil, fmt.Errorf("error loading services: %v", err)
	}

	return auth, nil
}

// -------------------- DataLoader --------------------

// AuthDataLoader declares an interface to load data from an auth service
type AuthDataLoader interface {
	// GetAccessToken gets an access token
	GetAccessToken(appID string, orgID string) error
	// GetAccessTokens get an access token for each app org pair a service account has access to
	GetAccessTokens() error
	ServiceRegLoader
}

//RemoteAuthDataLoaderImpl provides a AuthDataLoader implementation for a remote auth service
type RemoteAuthDataLoaderImpl struct {
	config *RemoteAuthDataLoaderConfig

	accessTokens *syncmap.Map
	appOrgPairs  []AppOrgPair

	tokensLock          *sync.RWMutex
	tokensUpdated       *time.Time
	maxRefreshCacheFreq uint

	timerDone               chan bool
	getDeletedAccountsTimer *time.Timer

	logger *logs.Logger

	*RemoteServiceRegLoaderImpl
}

//RemoteAuthDataLoaderConfig represents a configuration for a remote data loader
type RemoteAuthDataLoaderConfig struct {
	AuthServicesHost string // URL of auth services host
	ServiceAccountID string // Implementing service's account ID on the auth service

	AccessTokenPath     string // Path to auth service access token endpoint
	AccessTokensPath    string // Path to auth service access token endpoint
	DeletedAccountsPath string // Path to auth service deleted accounts endpoint
	ServiceRegPath      string // Path to auth service service registration endpoint

	ServiceAuthRequests ServiceAuthRequests

	DeletedAccountsCallback  func([]string) error // Function to call once the deleted accounts list is received from the auth service
	GetDeletedAccountsPeriod int64                // How often to request deleted account list from the auth service (in hours)
}

// buildAccessTokenRequest returns a HTTP request to get a single access token
func (r RemoteAuthDataLoaderConfig) buildAccessTokenRequest(appID string, orgID string) (*http.Request, error) {
	if r.AuthServicesHost == "" {
		return nil, errors.New("host is missing")
	}
	if r.AccessTokenPath == "" {
		return nil, errors.New("path is missing")
	}
	if r.ServiceAccountID == "" {
		return nil, errors.New("service account ID is missing")
	}
	if r.ServiceAuthRequests == nil {
		return nil, errors.New("service auth requests interface is not defined")
	}

	body := r.ServiceAuthRequests.BuildRequestAuthBody()
	body["account_id"] = r.ServiceAccountID
	body["app_id"] = appID
	body["org_id"] = orgID

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request body to get access token: %v", err)
	}

	req, err := http.NewRequest("POST", r.AuthServicesHost+r.AccessTokenPath, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("error formatting request to get access token: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	err = r.ServiceAuthRequests.ModifyRequest(req)
	if err != nil {
		return nil, fmt.Errorf("error modifying request to get access token: %v", err)
	}

	return req, nil
}

// buildAccessTokensRequest returns a HTTP request to get all allowed access tokens
func (r RemoteAuthDataLoaderConfig) buildAccessTokensRequest() (*http.Request, error) {
	if r.AuthServicesHost == "" {
		return nil, errors.New("host is missing")
	}
	if r.AccessTokensPath == "" {
		return nil, errors.New("path is missing")
	}
	if r.ServiceAccountID == "" {
		return nil, errors.New("service account ID is missing")
	}
	if r.ServiceAuthRequests == nil {
		return nil, errors.New("service auth requests interface is not defined")
	}

	body := r.ServiceAuthRequests.BuildRequestAuthBody()
	body["account_id"] = r.ServiceAccountID

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request body to get access tokens: %v", err)
	}

	req, err := http.NewRequest("POST", r.AuthServicesHost+r.AccessTokensPath, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("error formatting request to get access tokens: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	err = r.ServiceAuthRequests.ModifyRequest(req)
	if err != nil {
		return nil, fmt.Errorf("error modifying request to get access token: %v", err)
	}

	return req, nil
}

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

// NewStaticTokenServiceAuth creates a new StaticTokenServiceAuth instance
func NewStaticTokenServiceAuth(serviceToken string) (*StaticTokenServiceAuth, error) {
	if serviceToken == "" {
		return nil, fmt.Errorf("missing service token")
	}
	return &StaticTokenServiceAuth{ServiceToken: serviceToken}, nil
}

// AppOrgPair represents application organization pair access granted by a remote auth service
type AppOrgPair struct {
	AppID string
	OrgID string
}

// Equals checks if two AppOrgPairs are equivalent
func (ao AppOrgPair) Equals(other AppOrgPair) bool {
	return ao.AppID == other.AppID && ao.OrgID == other.OrgID
}

// AccessToken represents an access token granted by a remote auth service
type AccessToken struct {
	Token     string `json:"access_token"`
	TokenType string `json:"token_type"`
}

func (at AccessToken) String() string {
	return fmt.Sprintf("%s %s", at.TokenType, at.Token)
}

type accessTokensResponse struct {
	AppID       string      `json:"app_id"`
	OrgID       string      `json:"org_id"`
	AccessToken AccessToken `json:"token"`
}

// GetAccessToken implements AuthDataLoader interface
func (r *RemoteAuthDataLoaderImpl) GetAccessToken(appID string, orgID string) error {
	if r.config == nil {
		return fmt.Errorf("auth data loader is not configured")
	}
	req, err := r.config.buildAccessTokenRequest(appID, orgID)
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
		return fmt.Errorf("error parsing access token response: %v", err)
	}

	var accessToken AccessToken
	err = json.Unmarshal(body, &accessToken)
	if err != nil {
		return fmt.Errorf("error on unmarshal access token response: %v", err)
	}

	r.accessTokens.Store(AppOrgPair{AppID: appID, OrgID: orgID}, accessToken)

	return nil
}

// GetAccessTokens implements AuthDataLoader interface
func (r *RemoteAuthDataLoaderImpl) GetAccessTokens() error {
	if r.config == nil {
		return fmt.Errorf("auth data loader is not configured")
	}
	req, err := r.config.buildAccessTokensRequest()
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
		return fmt.Errorf("error parsing access tokens response: %v", err)
	}

	var accessTokens []accessTokensResponse
	err = json.Unmarshal(body, &accessTokens)
	if err != nil {
		return fmt.Errorf("error on unmarshal access tokens response: %v", err)
	}

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

// MakeRequest implements AuthDataLoader interface
func (r *RemoteAuthDataLoaderImpl) MakeRequest(req *http.Request, appID string, orgID string) (*http.Response, error) {
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
func (r *RemoteAuthDataLoaderImpl) CachedAccessTokens() map[AppOrgPair]AccessToken {
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

// CachedAppOrgPairs returns the data loader's cached app org pairs
func (r *RemoteAuthDataLoaderImpl) CachedAppOrgPairs() []AppOrgPair {
	return r.appOrgPairs
}

// ReadResponse reads the body of a http.Response and returns it
func (r *RemoteAuthDataLoaderImpl) ReadResponse(resp *http.Response) ([]byte, error) {
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

// getCachedAccessToken returns the most restrictive cached token (with corresponding pair) granting access to appOrgPair, if it exists
func (r *RemoteAuthDataLoaderImpl) getCachedAccessToken(appID string, orgID string) (*AccessToken, *AppOrgPair) {
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

// GetDeletedAccounts implements AuthDataLoader interface
func (r *RemoteAuthDataLoaderImpl) GetDeletedAccounts() ([]string, error) {
	idChan := make(chan []string)
	errChan := make(chan error)
	accountIDs := make([]string, 0)
	errStr := ""

	for _, pair := range r.appOrgPairs {
		go r.getDeletedAccountsAsync(pair, idChan, errChan)
	}

	for i := 0; i < len(r.appOrgPairs); i++ {
		partialAccountIDs := <-idChan
		partialErr := <-errChan
		if partialErr != nil {
			if len(errStr) > 0 {
				errStr += ", " + partialErr.Error()
			} else {
				errStr += partialErr.Error()
			}
		} else if partialAccountIDs != nil {
			accountIDs = append(accountIDs, partialAccountIDs...)
		}
	}

	if errStr != "" {
		return accountIDs, errors.New(errStr)
	}
	return accountIDs, nil
}

func (r *RemoteAuthDataLoaderImpl) getDeletedAccountsAsync(appOrgPair AppOrgPair, c chan []string, e chan error) {
	var req *http.Request
	var resp *http.Response
	var body []byte
	var deleted []string
	var err error

	if req, err = r.buildDeletedAccountsRequest(); err == nil {
		if resp, err = r.MakeRequest(req, appOrgPair.AppID, appOrgPair.OrgID); err == nil {
			if body, err = r.ReadResponse(resp); err == nil {
				err = json.Unmarshal(body, &deleted)
			}
		}
	}

	c <- deleted
	e <- err
}

func (r *RemoteAuthDataLoaderImpl) buildDeletedAccountsRequest() (*http.Request, error) {
	req, err := http.NewRequest("GET", r.config.AuthServicesHost+r.config.DeletedAccountsPath, nil)
	if err != nil {
		return nil, fmt.Errorf("error formatting request to get deleted accounts: %v", err)
	}

	return req, nil
}

// Deleted Accounts Timer

//StartGetDeletedAccountsTimer starts a timer which repeatedly requests deleted accounts from a remote auth service
func (r *RemoteAuthDataLoaderImpl) StartGetDeletedAccountsTimer() error {
	if r.config.DeletedAccountsCallback != nil {
		//cancel if active
		if r.getDeletedAccountsTimer != nil {
			r.timerDone <- true
			r.getDeletedAccountsTimer.Stop()
		}

		r.getDeletedAccounts(r.config.DeletedAccountsCallback)
	}
	return nil
}

func (r *RemoteAuthDataLoaderImpl) getDeletedAccounts(callback func([]string) error) {
	accountIDs, err := r.GetDeletedAccounts()
	if err != nil && r.logger != nil {
		r.logger.Error(err.Error())
	}

	err = callback(accountIDs)
	if err != nil && r.logger != nil {
		r.logger.Errorf("Received error from callback function: %v", err)
	}

	duration := time.Hour * time.Duration(r.config.GetDeletedAccountsPeriod)
	r.getDeletedAccountsTimer = time.NewTimer(duration)
	select {
	case <-r.getDeletedAccountsTimer.C:
		// timer expired
		r.getDeletedAccountsTimer = nil

		r.getDeletedAccounts(callback)
	case <-r.timerDone:
		// timer aborted
		r.getDeletedAccountsTimer = nil
	}
}

// SetMaxRefreshCacheFreq sets the maximum frequency at which cached access tokens are refreshed in minutes
// 	The default value is 30
func (r *RemoteAuthDataLoaderImpl) SetMaxRefreshCacheFreq(freq uint) {
	r.tokensLock.Lock()
	r.maxRefreshCacheFreq = freq
	r.tokensLock.Unlock()
}

//checkForRefresh checks if access tokens need to be reloaded
func (r *RemoteAuthDataLoaderImpl) checkForRefresh() (bool, error) {
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

// NewRemoteAuthDataLoader creates and configures a new NewRemoteAuthDataLoaderImpl instance for the provided auth services url
func NewRemoteAuthDataLoader(config *RemoteAuthDataLoaderConfig, subscribedServices []string, firstParty bool, logger *logs.Logger) (*RemoteAuthDataLoaderImpl, error) {
	if config == nil {
		return nil, errors.New("data loader config is missing")
	}
	if config.AuthServicesHost == "" {
		return nil, errors.New("auth services host is missing")
	}

	constructDataLoaderConfig(config, firstParty)

	serviceRegLoader := NewRemoteServiceRegLoader(subscribedServices)

	accessTokens := &syncmap.Map{}

	appOrgPairs := make([]AppOrgPair, 0)
	lock := &sync.RWMutex{}

	timerDone := make(chan bool)

	dataLoader := RemoteAuthDataLoaderImpl{config: config, accessTokens: accessTokens, maxRefreshCacheFreq: 30, tokensLock: lock,
		appOrgPairs: appOrgPairs, timerDone: timerDone, logger: logger, RemoteServiceRegLoaderImpl: serviceRegLoader}
	serviceRegLoader.dataLoader = &dataLoader

	return &dataLoader, nil
}

func constructDataLoaderConfig(config *RemoteAuthDataLoaderConfig, firstParty bool) {
	pathPrefix := "/bbs"
	if !firstParty {
		pathPrefix = "/tps"
	}
	if config.AccessTokenPath == "" {
		config.AccessTokenPath = pathPrefix + "/access-token"
	}
	if config.AccessTokensPath == "" {
		config.AccessTokensPath = pathPrefix + "/access-tokens"
	}
	if config.DeletedAccountsPath == "" {
		config.DeletedAccountsPath = pathPrefix + "/deleted-accounts"
	}
	if config.ServiceRegPath == "" {
		config.ServiceRegPath = pathPrefix + "/service-regs"
	}

	if config.DeletedAccountsCallback != nil {
		if config.GetDeletedAccountsPeriod <= 0 {
			config.GetDeletedAccountsPeriod = 2
		}
	}
}

// -------------------- ServiceRegLoader --------------------

// ServiceRegLoader declares an interface to load the service registrations for specified services
type ServiceRegLoader interface {
	// LoadServices loads the service registration records for all subscribed services
	LoadServices() ([]ServiceReg, error)
	//GetSubscribedServices returns the list of currently subscribed services
	GetSubscribedServices() []string
	// SubscribeService subscribes the loader to the given service
	// 	Returns true if the specified service was added or false if it was already found
	SubscribeService(serviceID string) bool
	// UnsubscribeService unsubscribes the loader from the given service
	// 	Returns true if the specified service was removed or false if it was not found
	UnsubscribeService(serviceID string) bool
}

//RemoteServiceRegLoaderImpl provides a ServiceRegLoader implementation for a remote auth service
type RemoteServiceRegLoaderImpl struct {
	dataLoader *RemoteAuthDataLoaderImpl

	*ServiceRegSubscriptions
}

// LoadServices implements ServiceRegLoader interface
func (r *RemoteServiceRegLoaderImpl) LoadServices() ([]ServiceReg, error) {
	if len(r.GetSubscribedServices()) == 0 {
		return nil, nil
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", r.dataLoader.config.AuthServicesHost+r.dataLoader.config.ServiceRegPath, nil)
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

// NewRemoteServiceRegLoader creates and configures a new RemoteServiceRegLoaderImpl instance for the provided auth services url
func NewRemoteServiceRegLoader(subscribedServices []string) *RemoteServiceRegLoaderImpl {
	subscriptions := NewServiceRegSubscriptions(subscribedServices)
	return &RemoteServiceRegLoaderImpl{ServiceRegSubscriptions: subscriptions}
}

// -------------------- ServiceRegSubscriptions --------------------

// ServiceRegSubscriptions defined a struct to hold service registration subscriptions
// 	This struct implements the subcription part of the ServiceRegLoader interface
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
