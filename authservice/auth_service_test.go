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

package authservice_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/rokwire/core-auth-library-go/v2/authservice"
	"github.com/rokwire/core-auth-library-go/v2/authutils"
	"github.com/rokwire/core-auth-library-go/v2/internal/testutils"
	"github.com/rokwire/core-auth-library-go/v2/keys"
)

func setupSampleServiceRegSubscriptions() *authservice.ServiceRegSubscriptions {
	return authservice.NewServiceRegSubscriptions([]string{"auth", "test"})
}

func TestServiceRegManager_GetServiceReg(t *testing.T) {
	authPubKey, err := testutils.GetSamplePubKey()
	if err != nil {
		t.Errorf("Error getting sample pubkey: %v", err)
		return
	}

	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")
	testServiceReg := authservice.ServiceReg{authService.ServiceID, "dec8d277-b775-47a2-b7b0-ce8482871b67", authService.ServiceHost, nil}
	authServiceReg := authservice.ServiceReg{"auth", "6050ec62-d552-4fed-b11f-15a01bb1afc1", "https://auth.rokwire.com", authPubKey}

	serviceRegs := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	type args struct {
		id string
	}
	tests := []struct {
		name    string
		args    args
		want    *authservice.ServiceReg
		wantErr bool
	}{
		{"return reg when found by serviceID", args{"auth"}, &authServiceReg, false},
		{"return reg when found by serviceAccountID", args{"6050ec62-d552-4fed-b11f-15a01bb1afc1"}, &authServiceReg, false},
		{"return err when not found", args{"example"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := testutils.SetupTestServiceRegManager(authService, testutils.SetupMockServiceRegLoader(authService, subscribed, serviceRegs, nil))
			if err != nil || m == nil {
				t.Errorf("Error initializing test auth service: %v", err)
				return
			}
			got, err := m.GetServiceReg(tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ServiceRegManager.GetServiceReg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ServiceRegManager.GetServiceReg() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServiceRegManager_GetServiceRegWithPubKey(t *testing.T) {
	authPubKey, err := testutils.GetSamplePubKey()
	if err != nil {
		t.Errorf("Error getting sample pubkey: %v", err)
		return
	}

	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")
	testServiceReg := authservice.ServiceReg{authService.ServiceID, "dec8d277-b775-47a2-b7b0-ce8482871b67", authService.ServiceHost, nil}
	authServiceReg := authservice.ServiceReg{"auth", "6050ec62-d552-4fed-b11f-15a01bb1afc1", "https://auth.rokwire.com", authPubKey}

	serviceRegs := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	type args struct {
		id string
	}
	tests := []struct {
		name    string
		args    args
		want    *authservice.ServiceReg
		wantErr bool
	}{
		{"return reg when found by serviceID and key valid", args{"auth"}, &authServiceReg, false},
		{"return reg when found by serviceAccountID and key valid", args{"6050ec62-d552-4fed-b11f-15a01bb1afc1"}, &authServiceReg, false},
		{"return err when found and key invalid", args{"test"}, nil, true},
		{"return err when not found", args{"example"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := testutils.SetupTestServiceRegManager(authService, testutils.SetupMockServiceRegLoader(authService, subscribed, serviceRegs, nil))
			if err != nil || m == nil {
				t.Errorf("Error initializing test auth service: %v", err)
				return
			}
			got, err := m.GetServiceRegWithPubKey(tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ServiceRegManager.GetServiceRegWithPubKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ServiceRegManager.GetServiceRegWithPubKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServiceRegManager_SubscribeServices(t *testing.T) {
	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")
	testServiceReg := authservice.ServiceReg{authService.ServiceID, "dec8d277-b775-47a2-b7b0-ce8482871b67", authService.ServiceHost, nil}
	authServiceReg := authservice.ServiceReg{"auth", "6050ec62-d552-4fed-b11f-15a01bb1afc1", "https://auth.rokwire.com", nil}
	serviceRegs := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	type args struct {
		serviceIDs []string
		reload     bool
	}
	tests := []struct {
		name         string
		args         args
		shouldReload bool
	}{
		{"reload when not found and reload is true", args{[]string{"new", "auth"}, true}, true},
		{"don't reload when found", args{[]string{"auth"}, true}, false},
		{"don't reload when reload is false", args{[]string{"new"}, false}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceRegLoader(authService, subscribed, serviceRegs, nil)
			m, err := testutils.SetupTestServiceRegManager(authService, mockLoader)
			if err != nil || m == nil {
				t.Errorf("Error initializing test auth service: %v", err)
				return
			}
			m.SubscribeServices(tt.args.serviceIDs, tt.args.reload)
			subscriptions := mockLoader.GetSubscribedServices()
			for _, val := range tt.args.serviceIDs {
				if !authutils.ContainsString(subscriptions, val) {
					t.Errorf("expected added subscriptions: %v, got %v", tt.args.serviceIDs, subscriptions)
					return
				}
			}
			expectedCalls := 1
			if tt.shouldReload {
				expectedCalls = 2
			}
			mockLoader.AssertNumberOfCalls(t, "LoadServices", expectedCalls)
		})
	}
}

func TestServiceRegManager_ValidateServiceRegistration(t *testing.T) {
	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")
	testServiceReg := authservice.ServiceReg{authService.ServiceID, "dec8d277-b775-47a2-b7b0-ce8482871b67", authService.ServiceHost, nil}
	test2ServiceReg := authservice.ServiceReg{authService.ServiceID, "dec8d277-b775-47a2-b7b0-ce8482871b67", "https://test2.rokwire.com", nil}
	authServiceReg := authservice.ServiceReg{"auth", "6050ec62-d552-4fed-b11f-15a01bb1afc1", "https://auth.rokwire.com", nil}

	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}
	serviceRegsMissing := []authservice.ServiceReg{authServiceReg}
	serviceRegsInvalid := []authservice.ServiceReg{authServiceReg, test2ServiceReg}
	subscribed := []string{"auth"}

	tests := []struct {
		name             string
		loadServicesResp []authservice.ServiceReg
		wantErr          bool
	}{
		{"no error on registration found", serviceRegsValid, false},
		{"error on registration not found", serviceRegsMissing, true},
		{"error on wrong registration host", serviceRegsInvalid, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceRegLoader(authService, subscribed, tt.loadServicesResp, nil)
			m, err := testutils.SetupTestServiceRegManager(authService, mockLoader)
			if err != nil || m == nil {
				t.Errorf("Error initializing test auth service: %v", err)
				return
			}
			if err := m.ValidateServiceRegistration(); (err != nil) != tt.wantErr {
				t.Errorf("ServiceRegManager.ValidateServiceRegistration() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthService_ValidateServiceRegistrationKey(t *testing.T) {
	pubKey, err := testutils.GetSamplePubKey()
	if err != nil {
		t.Errorf("Error getting sample pubkey: %v", err)
		return
	}
	_, wrongKey, err := keys.NewAsymmetricKeyPair(authutils.RS256, 2048)
	if err != nil {
		t.Errorf("Error generating new pubkey: %v", err)
		return
	}

	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")
	testServiceReg := authservice.ServiceReg{authService.ServiceID, "dec8d277-b775-47a2-b7b0-ce8482871b67", authService.ServiceHost, pubKey}
	testServiceRegNoKey := authservice.ServiceReg{authService.ServiceID, "dec8d277-b775-47a2-b7b0-ce8482871b67", authService.ServiceHost, nil}
	testServiceRegWrongKey := authservice.ServiceReg{authService.ServiceID, "dec8d277-b775-47a2-b7b0-ce8482871b67", authService.ServiceHost, wrongKey}

	authServiceReg := authservice.ServiceReg{"auth", "6050ec62-d552-4fed-b11f-15a01bb1afc1", "https://auth.rokwire.com", nil}

	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}
	serviceRegsMissing := []authservice.ServiceReg{authServiceReg}
	serviceRegsNoKey := []authservice.ServiceReg{authServiceReg, testServiceRegNoKey}
	serviceRegsWrongKey := []authservice.ServiceReg{authServiceReg, testServiceRegWrongKey}

	subscribed := []string{"auth"}

	privKey, err := testutils.GetSamplePrivKey()
	if err != nil {
		t.Errorf("Error getting sample privkey: %v", err)
		return
	}

	type args struct {
		privKey *keys.PrivKey
	}
	tests := []struct {
		name             string
		args             args
		loadServicesResp []authservice.ServiceReg
		wantErr          bool
	}{
		{"no error on registration found", args{privKey}, serviceRegsValid, false},
		{"error on registration not found", args{privKey}, serviceRegsMissing, true},
		{"error on missing registration key", args{privKey}, serviceRegsNoKey, true},
		{"error on wrong registration key", args{privKey}, serviceRegsWrongKey, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceRegLoader(authService, subscribed, tt.loadServicesResp, nil)
			m, err := testutils.SetupTestServiceRegManager(authService, mockLoader)
			if err != nil || m == nil {
				t.Errorf("Error initializing test auth service: %v", err)
				return
			}
			if err := m.ValidateServiceRegistrationKey(tt.args.privKey); (err != nil) != tt.wantErr {
				t.Errorf("ServiceRegManager.ValidateServiceRegistrationKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestServiceRegSubscriptions_SubscribeService(t *testing.T) {
	type args struct {
		serviceID string
	}
	tests := []struct {
		name         string
		args         args
		want         bool
		wantServices []string
	}{
		{"return true and add service when missing", args{"test2"}, true, []string{"auth", "test", "test2"}},
		{"return false and don't add service when found", args{"test"}, false, []string{"auth", "test"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := setupSampleServiceRegSubscriptions()
			if got := r.SubscribeService(tt.args.serviceID); got != tt.want {
				t.Errorf("ServiceRegSubscriptions.SubscribeService() = %v, want %v", got, tt.want)
			}
			if gotServices := r.GetSubscribedServices(); !reflect.DeepEqual(gotServices, tt.wantServices) {
				t.Errorf("ServiceRegSubscriptions.SubscribeService() services: got %v, want %v", gotServices, tt.wantServices)
			}
		})
	}
}

func TestServiceRegSubscriptions_UnsubscribeService(t *testing.T) {
	type args struct {
		serviceID string
	}
	tests := []struct {
		name         string
		args         args
		want         bool
		wantServices []string
	}{
		{"return true and remove service when found", args{"test"}, true, []string{"auth"}},
		{"return false and don't modify services when missing", args{"test2"}, false, []string{"auth", "test"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := setupSampleServiceRegSubscriptions()
			if got := r.UnsubscribeService(tt.args.serviceID); got != tt.want {
				t.Errorf("ServiceRegSubscriptions.UnsubscribeService() = %v, want %v", got, tt.want)
			}
			if gotServices := r.GetSubscribedServices(); !reflect.DeepEqual(gotServices, tt.wantServices) {
				t.Errorf("ServiceRegSubscriptions.UnsubscribeService() services: got %v, want %v", gotServices, tt.wantServices)
			}
		})
	}
}

func TestServiceAccountManager_GetAccessToken(t *testing.T) {
	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")

	type args struct {
		appID string
		orgID string
		token *authservice.AccessToken
		err   error

		readAppID string
		readOrgID string
	}
	tests := []struct {
		name        string
		args        args
		want        string
		wantLoadErr bool
		wantReadErr bool
	}{
		{"successfully read stored token", args{"4f684d01-8a8c-4674-9005-942c16136ab6", "8a145f9e-bb5d-4f4c-8af0-a43527c05d16", &authservice.AccessToken{Token: "sample_token", TokenType: "Bearer"}, nil, "4f684d01-8a8c-4674-9005-942c16136ab6", "8a145f9e-bb5d-4f4c-8af0-a43527c05d16"}, "Bearer sample_token", false, false},
		{"attempt to read unknown token", args{"9b25622b-e559-4824-9ea7-535c8b990725", "c83338f7-5fe9-47ac-b432-22fb987eb9f7", &authservice.AccessToken{Token: "sample_token", TokenType: "Bearer"}, nil, "4f684d01-8a8c-4674-9005-942c16136ab6", "8a145f9e-bb5d-4f4c-8af0-a43527c05d16"}, "", false, true},
		{"loading error", args{"4f684d01-8a8c-4674-9005-942c16136ab6", "8a145f9e-bb5d-4f4c-8af0-a43527c05d16", nil, errors.New("loading error"), "4f684d01-8a8c-4674-9005-942c16136ab6", "8a145f9e-bb5d-4f4c-8af0-a43527c05d16"}, "", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceAccountTokenLoader(authService, tt.args.appID, tt.args.orgID, tt.args.token, tt.args.err)
			mockManager, _ := testutils.SetupTestServiceAccountManager(authService, mockLoader, false)

			got, err := mockManager.GetAccessToken(tt.args.appID, tt.args.orgID)
			if (err != nil) != tt.wantLoadErr {
				t.Errorf("ServiceAccountManager.GetAccessToken() err = %v, wantLoadErr %v", err, tt.wantLoadErr)
			}

			stored := mockManager.AccessTokens()[authservice.AppOrgPair{AppID: tt.args.readAppID, OrgID: tt.args.readOrgID}]
			if tt.wantReadErr != (stored.String() == "") {
				t.Errorf("ServiceAccountManager.GetAccessToken() err = %v, wantReadErr %v", err, tt.wantReadErr)
			} else if !tt.wantReadErr && (got.String() != stored.String()) {
				t.Errorf("ServiceAccountManager.GetAccessToken() got = %s, want %s", got.String(), tt.want)
			}
		})
	}
}

func TestServiceAccountManager_GetAccessTokens(t *testing.T) {
	tokens := map[authservice.AppOrgPair]authservice.AccessToken{
		{AppID: authutils.AllApps, OrgID: "0716d801-ee13-4428-b10b-e52c6d989dcc"}:                      {Token: "all_apps_token", TokenType: "Bearer"},
		{AppID: "4f684d01-8a8c-4674-9005-942c16136ab6", OrgID: "8a145f9e-bb5d-4f4c-8af0-a43527c05d16"}: {Token: "specific_token", TokenType: "Bearer"},
	}

	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")

	type args struct {
		appID  string
		orgID  string
		tokens map[authservice.AppOrgPair]authservice.AccessToken
		err    error
	}
	tests := []struct {
		name        string
		args        args
		want        string
		wantLoadErr bool
		wantReadErr bool
	}{
		{"successfully read stored apps token", args{authutils.AllApps, "0716d801-ee13-4428-b10b-e52c6d989dcc", tokens, nil}, "Bearer all_apps_token", false, false},
		{"successfully read stored specific token", args{"4f684d01-8a8c-4674-9005-942c16136ab6", "8a145f9e-bb5d-4f4c-8af0-a43527c05d16", tokens, nil}, "Bearer specific_token", false, false},
		{"attempt to read unknown token", args{"9b25622b-e559-4824-9ea7-535c8b990725", "c83338f7-5fe9-47ac-b432-22fb987eb9f7", tokens, nil}, "", false, true},
		{"loading error", args{"4f684d01-8a8c-4674-9005-942c16136ab6", "8a145f9e-bb5d-4f4c-8af0-a43527c05d16", nil, errors.New("loading error")}, "", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceAccountTokensLoader(authService, tt.args.tokens, tt.args.err)
			mockManager, _ := testutils.SetupTestServiceAccountManager(authService, mockLoader, tt.args.err == nil)

			tokens, _, err := mockManager.GetAccessTokens()
			if (err != nil) != tt.wantLoadErr {
				t.Errorf("ServiceAccountManager.GetAccessTokens() err = %v, wantLoadErr %v", err, tt.wantLoadErr)
			} else if !tt.wantLoadErr && tokens != nil {
				got := tokens[authservice.AppOrgPair{AppID: tt.args.appID, OrgID: tt.args.orgID}]
				stored := mockManager.AccessTokens()[authservice.AppOrgPair{AppID: tt.args.appID, OrgID: tt.args.orgID}]
				if tt.wantReadErr != (stored.String() == "") {
					t.Errorf("ServiceAccountManager.GetAccessTokens() err = %v, wantReadErr %v", err, tt.wantReadErr)
				} else if !tt.wantReadErr && (got.String() != stored.String()) {
					t.Errorf("ServiceAccountManager.GetAccessTokens() got = %s, want %s", got.String(), tt.want)
				}
			}
		})
	}
}

func TestServiceAccountManager_GetCachedAccessToken(t *testing.T) {
	allAllTokens := map[authservice.AppOrgPair]authservice.AccessToken{
		{AppID: authutils.AllApps, OrgID: authutils.AllOrgs}: {Token: "all_all_token", TokenType: "Bearer"},
	}
	allAppTokens := map[authservice.AppOrgPair]authservice.AccessToken{
		{AppID: authutils.AllApps, OrgID: "0716d801-ee13-4428-b10b-e52c6d989dcc"}: {Token: "all_apps_token", TokenType: "Bearer"},
	}
	allOrgTokens := map[authservice.AppOrgPair]authservice.AccessToken{
		{AppID: "83f0ed91-6e27-4101-8c44-c4d7e9115767", OrgID: authutils.AllOrgs}: {Token: "all_orgs_token", TokenType: "Bearer"},
	}
	specificTokens := map[authservice.AppOrgPair]authservice.AccessToken{
		{AppID: "4f684d01-8a8c-4674-9005-942c16136ab6", OrgID: "8a145f9e-bb5d-4f4c-8af0-a43527c05d16"}: {Token: "specific_token", TokenType: "Bearer"},
	}

	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")

	type args struct {
		appID  string
		orgID  string
		tokens map[authservice.AppOrgPair]authservice.AccessToken
	}
	tests := []struct {
		name      string
		args      args
		wantToken string
		wantPair  string
		wantErr   bool
	}{
		{"all_all exact match", args{authutils.AllApps, authutils.AllOrgs, allAllTokens}, "Bearer all_all_token", "all_all", false},
		{"all_all apps match", args{authutils.AllApps, "0716d801-ee13-4428-b10b-e52c6d989dcc", allAllTokens}, "Bearer all_all_token", "all_all", false},
		{"all_all orgs match", args{"83f0ed91-6e27-4101-8c44-c4d7e9115767", authutils.AllOrgs, allAllTokens}, "Bearer all_all_token", "all_all", false},
		{"all_all specific pair match", args{"b38a5f4f-3f7c-4909-90b6-9188701031da", "c83338f7-5fe9-47ac-b432-22fb987eb9f7", allAllTokens}, "Bearer all_all_token", "all_all", false},

		{"all_all apps mismatch", args{authutils.AllApps, authutils.AllOrgs, allAppTokens}, "", "", true},
		{"all_apps exact match", args{authutils.AllApps, "0716d801-ee13-4428-b10b-e52c6d989dcc", allAppTokens}, "Bearer all_apps_token", "all_0716d801-ee13-4428-b10b-e52c6d989dcc", false},
		{"all_orgs mismatch", args{"83f0ed91-6e27-4101-8c44-c4d7e9115767", authutils.AllOrgs, allAppTokens}, "", "", true},
		{"all_apps specific pair match", args{"44ada4a9-7f75-4e26-994d-fda4212ac0a2", "0716d801-ee13-4428-b10b-e52c6d989dcc", allAppTokens}, "Bearer all_apps_token", "all_0716d801-ee13-4428-b10b-e52c6d989dcc", false},
		{"all_apps specific pair mismatch", args{"44ada4a9-7f75-4e26-994d-fda4212ac0a2", "9b25622b-e559-4824-9ea7-535c8b990725", allAppTokens}, "", "", true},

		{"all_all orgs mismatch", args{authutils.AllApps, authutils.AllOrgs, allOrgTokens}, "", "", true},
		{"all_apps mismatch", args{authutils.AllApps, "0716d801-ee13-4428-b10b-e52c6d989dcc", allOrgTokens}, "", "", true},
		{"all_orgs exact match", args{"83f0ed91-6e27-4101-8c44-c4d7e9115767", authutils.AllOrgs, allOrgTokens}, "Bearer all_orgs_token", "83f0ed91-6e27-4101-8c44-c4d7e9115767_all", false},
		{"all_orgs specific pair match", args{"83f0ed91-6e27-4101-8c44-c4d7e9115767", "a09d7427-9424-4b51-9aaf-ca376388911e", allOrgTokens}, "Bearer all_orgs_token", "83f0ed91-6e27-4101-8c44-c4d7e9115767_all", false},
		{"all_orgs specific pair mismatch", args{"6dfdf936-5042-4b93-a82d-220672d8bca1", "a09d7427-9424-4b51-9aaf-ca376388911e", allOrgTokens}, "", "", true},

		{"specific all_all mismatch", args{authutils.AllApps, authutils.AllOrgs, specificTokens}, "", "", true},
		{"specific all apps mismatch", args{authutils.AllApps, "8a145f9e-bb5d-4f4c-8af0-a43527c05d16", specificTokens}, "", "", true},
		{"specific all orgs mismatch", args{"4f684d01-8a8c-4674-9005-942c16136ab6", authutils.AllOrgs, specificTokens}, "", "", true},
		{"specific app mismatch", args{"6dfdf936-5042-4b93-a82d-220672d8bca1", "8a145f9e-bb5d-4f4c-8af0-a43527c05d16", specificTokens}, "", "", true},
		{"specific org mismatch", args{"4f684d01-8a8c-4674-9005-942c16136ab6", "a09d7427-9424-4b51-9aaf-ca376388911e", specificTokens}, "", "", true},
		{"specific exact match", args{"4f684d01-8a8c-4674-9005-942c16136ab6", "8a145f9e-bb5d-4f4c-8af0-a43527c05d16", specificTokens}, "Bearer specific_token", "4f684d01-8a8c-4674-9005-942c16136ab6_8a145f9e-bb5d-4f4c-8af0-a43527c05d16", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceAccountTokensLoader(authService, tt.args.tokens, nil)
			mockManager, _ := testutils.SetupTestServiceAccountManager(authService, mockLoader, true)

			token, pair := mockManager.GetCachedAccessToken(tt.args.appID, tt.args.orgID)
			if (tt.wantToken == "") != tt.wantErr {
				t.Errorf("ServiceAccountManager.GetCachedAccessToken() token = %s, wantErr %v", token.String(), tt.wantErr)
			} else if !tt.wantErr && (token.String() != tt.wantToken) {
				t.Errorf("ServiceAccountManager.GetCachedAccessToken() token = %s, want %s", token.String(), tt.wantToken)
			}
			if (tt.wantPair == "") != tt.wantErr {
				t.Errorf("ServiceAccountManager.GetCachedAccessToken() pair = %s, wantErr %v", pair.String(), tt.wantErr)
			} else if !tt.wantErr && (pair.String() != tt.wantPair) {
				t.Errorf("ServiceAccountManager.GetCachedAccessToken() pair = %s, want %s", pair.String(), tt.wantPair)
			}
		})
	}
}
