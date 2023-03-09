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

package tokenauth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/rokwire/core-auth-library-go/v2/authorization"
	"github.com/rokwire/core-auth-library-go/v2/authservice"
	"github.com/rokwire/core-auth-library-go/v2/authservice/mocks"
	"github.com/rokwire/core-auth-library-go/v2/authutils"
	"github.com/rokwire/core-auth-library-go/v2/internal/testutils"
	"github.com/rokwire/core-auth-library-go/v2/keys"
	"github.com/rokwire/core-auth-library-go/v2/tokenauth"
)

func setupTestTokenAuth(authService *authservice.AuthService, acceptRokwire bool, mockLoader *mocks.ServiceRegLoader) (*tokenauth.TokenAuth, error) {
	manager, err := testutils.SetupTestServiceRegManager(authService, mockLoader)
	if err != nil {
		return nil, fmt.Errorf("error setting up test auth service: %v", err)
	}
	permissionAuth := authorization.NewCasbinStringAuthorization("./test_permissions_authorization_policy.csv")
	scopeAuth := authorization.NewCasbinScopeAuthorization("./test_scope_authorization_policy.csv", "sample")
	return tokenauth.NewTokenAuth(acceptRokwire, manager, permissionAuth, scopeAuth)
}

func getTestClaims(sub string, aud string, orgID string, purpose string, issuer string, permissions string, scope string, auth_type string, exp int64) *tokenauth.Claims {
	return &tokenauth.Claims{
		StandardClaims: jwt.StandardClaims{
			Audience:  aud,
			Subject:   sub,
			ExpiresAt: exp,
			IssuedAt:  time.Now().Unix(),
			Issuer:    issuer,
		}, OrgID: orgID, Purpose: purpose, Permissions: permissions, Scope: scope, AuthType: auth_type,
	}
}

func getSampleValidClaims() *tokenauth.Claims {
	exp := time.Now().Add(30 * time.Minute)
	return getTestClaims("test_user_id", "rokwire", "test_org_id", "access",
		"https://auth.rokwire.com", "example_permission,test_permission,sample_admin", "all:all:all", "email", exp.Unix())
}

func getSampleExpiredClaims() *tokenauth.Claims {
	exp := time.Now().Add(-5 * time.Minute)
	return getTestClaims("test_user_id", "rokwire", "test_org_id", "access",
		"https://auth.rokwire.com", "example_permission", "all:all:all", "email", exp.Unix())
}

func TestClaims_CanAccess(t *testing.T) {
	systemClaims := tokenauth.Claims{AppID: "app1", OrgID: "org1", System: true}
	adminClaims := tokenauth.Claims{AppID: "app1", OrgID: "org1"}
	serviceClaims := tokenauth.Claims{AppID: "app1", OrgID: "org1", Service: true}
	serviceClaimsAll := tokenauth.Claims{AppID: authutils.AllApps, OrgID: authutils.AllOrgs, Service: true}
	serviceClaimsAllApps := tokenauth.Claims{AppID: authutils.AllApps, OrgID: "org1", Service: true}

	type args struct {
		claims *tokenauth.Claims
		appID  string
		orgID  string
		system bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"success on system access all_all", args{&systemClaims, authutils.AllApps, authutils.AllOrgs, true}, false},
		{"success on system access all_org", args{&systemClaims, authutils.AllApps, "org1", false}, false},
		{"success on system access app_all", args{&systemClaims, "app1", authutils.AllOrgs, true}, false},
		{"success on system access app_org", args{&systemClaims, "app1", "org1", true}, false},
		{"error on access other app_org", args{&systemClaims, "app1", "org2", true}, true},

		{"error on admin access all_all_system", args{&adminClaims, authutils.AllApps, authutils.AllOrgs, true}, true},
		{"error on admin access all_all", args{&adminClaims, authutils.AllApps, authutils.AllOrgs, false}, true},
		{"success on admin access all_org", args{&adminClaims, authutils.AllApps, "org1", false}, false},
		{"error on admin access app_all_system", args{&adminClaims, "app1", authutils.AllOrgs, true}, true},
		{"error on admin access app_all", args{&adminClaims, "app1", authutils.AllOrgs, false}, true},
		{"success on admin access app_org", args{&adminClaims, "app1", "org1", false}, false},
		{"error on access system resource", args{&adminClaims, "app1", "org1", true}, true},

		{"error on service access all_all_system", args{&serviceClaimsAll, authutils.AllApps, authutils.AllOrgs, true}, true},
		{"error on service access all_all", args{&serviceClaimsAll, authutils.AllApps, authutils.AllOrgs, false}, false},
		{"success on service access all_org", args{&serviceClaimsAll, authutils.AllApps, "org1", false}, false},
		{"error on service access app_all", args{&serviceClaimsAll, "app1", authutils.AllOrgs, true}, true},
		{"success on all service access app_org", args{&serviceClaimsAll, "app1", "org1", false}, false},
		{"success on all apps service access app_org", args{&serviceClaimsAllApps, "app1", "org1", false}, false},
		{"success on service access app_org", args{&serviceClaims, "app1", "org1", false}, false},
		{"error on access system resource", args{&serviceClaims, "app1", "org1", true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.args.claims.CanAccess(tt.args.appID, tt.args.orgID, tt.args.system)
			if (err != nil) != tt.wantErr {
				t.Errorf("Claims.CanAccess() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTokenAuth_CheckToken(t *testing.T) {
	pubKey, err := testutils.GetSamplePubKey(keys.RS256)
	if err != nil {
		t.Errorf("Error getting sample pubkey: %v", err)
		return
	}

	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")
	testServiceReg := authservice.ServiceReg{ServiceID: authService.ServiceID, Host: authService.ServiceHost, PubKey: nil}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokwire.com", PubKey: pubKey}
	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	samplePrivKey, err := testutils.GetSamplePrivKey(keys.RS256)
	if err != nil {
		t.Errorf("Error getting sample privkey: %v", err)
		return
	}

	// Valid rokwire
	validClaims := getSampleValidClaims()
	validToken, err := tokenauth.GenerateSignedToken(validClaims, samplePrivKey)
	if err != nil {
		t.Errorf("Error initializing valid token: %v", err)
	}

	// Valid audience
	validAudClaims := getSampleValidClaims()
	validAudClaims.Audience = "test"
	validAudToken, err := tokenauth.GenerateSignedToken(validAudClaims, samplePrivKey)
	if err != nil {
		t.Errorf("Error initializing valid aud token: %v", err)
	}

	// Expired
	expiredToken, err := tokenauth.GenerateSignedToken(getSampleExpiredClaims(), samplePrivKey)
	if err != nil {
		t.Errorf("Error initializing expired token: %v", err)
	}

	// Invalid issuer
	invalidIssClaims := getSampleValidClaims()
	invalidIssClaims.Issuer = "https://auth2.rokwire.com"
	invalidIssToken, err := tokenauth.GenerateSignedToken(invalidIssClaims, samplePrivKey)
	if err != nil {
		t.Errorf("Error initializing invalid iss token: %v", err)
	}

	// Invalid audience
	invalidAudClaims := getSampleValidClaims()
	invalidAudClaims.Audience = "test2"
	invalidAudToken, err := tokenauth.GenerateSignedToken(invalidAudClaims, samplePrivKey)
	if err != nil {
		t.Errorf("Error initializing invalid aud token: %v", err)
	}

	type args struct {
		token   string
		purpose string
	}
	tests := []struct {
		name          string
		args          args
		acceptRokwire bool
		want          *tokenauth.Claims
		wantErr       bool
		errSubstring  string
	}{
		{"return claims on valid rokwire token", args{validToken, "access"}, true, validClaims, false, ""},
		{"return claims on valid aud token", args{validAudToken, "access"}, false, validAudClaims, false, ""},
		{"return error on invalid token", args{"token", "access"}, true, nil, true, "failed to parse token"},
		{"return error on expired token", args{expiredToken, "access"}, true, nil, true, "token is expired"},
		{"return error on wrong issuer", args{invalidIssToken, "access"}, true, nil, true, ""},
		{"return error on wrong aud", args{invalidAudToken, "access"}, true, nil, true, ""},
		{"return error on wrong purpose", args{validToken, "csrf"}, true, nil, true, ""},
		{"return error on unpermitted rokwire token", args{validToken, "access"}, false, nil, true, ""},
		//TODO: Fill <invalid retry token> and <valid token after refresh> placeholders
		// {"return error on retry invalid token", args{"<invalid retry token>", "access"}, true, nil, true, "initial token check returned invalid, error on retry"},
		// {"return claims after refresh", args{"<valid token after refresh>", "access"}, true, &tokenauth.Claims{}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceRegLoader(authService, subscribed, serviceRegsValid, nil)
			tr, err := setupTestTokenAuth(authService, tt.acceptRokwire, mockLoader)
			if err != nil || tr == nil {
				t.Errorf("Error initializing test token auth: %v", err)
				return
			}
			got, err := tr.CheckToken(tt.args.token, tt.args.purpose)
			if (err != nil) != tt.wantErr {
				t.Errorf("TokenAuth.CheckToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errSubstring) {
				t.Errorf("TokenAuth.CheckToken() error = %v, errSubstring %s", err, tt.errSubstring)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TokenAuth.CheckToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenAuth_CheckRequestToken(t *testing.T) {
	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")
	testServiceReg := authservice.ServiceReg{ServiceID: authService.ServiceID, Host: authService.ServiceHost, PubKey: nil}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokwire.com", PubKey: nil}
	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    *tokenauth.Claims
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceRegLoader(authService, subscribed, serviceRegsValid, nil)
			tr, err := setupTestTokenAuth(authService, true, mockLoader)
			if err != nil || tr == nil {
				t.Errorf("Error initializing test token auth: %v", err)
				return
			}
			got, err := tr.CheckRequestToken(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("TokenAuth.CheckRequestToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TokenAuth.CheckRequestToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenAuth_ValidatePermissionsClaim(t *testing.T) {
	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")

	type args struct {
		claims              *tokenauth.Claims
		requiredPermissions []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, err := setupTestTokenAuth(authService, true, nil)
			if err != nil || tr == nil {
				t.Errorf("Error initializing test token auth: %v", err)
				return
			}
			if err := tr.ValidatePermissionsClaim(tt.args.claims, tt.args.requiredPermissions); (err != nil) != tt.wantErr {
				t.Errorf("TokenAuth.ValidatePermissionsClaim() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTokenAuth_ValidateScopeClaim(t *testing.T) {
	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")

	type args struct {
		claims        *tokenauth.Claims
		requiredScope string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, err := setupTestTokenAuth(authService, true, nil)
			if err != nil || tr == nil {
				t.Errorf("Error initializing test token auth: %v", err)
				return
			}
			if err := tr.ValidateScopeClaim(tt.args.claims, tt.args.requiredScope); (err != nil) != tt.wantErr {
				t.Errorf("TokenAuth.ValidateScopeClaim() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetAccessToken(t *testing.T) {
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tokenauth.GetAccessToken(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("TestGetAccessToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("TestGetAccessToken() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateSignedToken(t *testing.T) {
	validClaims := getSampleValidClaims()
	key, err := testutils.GetSamplePrivKey(keys.RS256)
	if err != nil {
		t.Errorf("Error getting sample privkey: %v", err)
		return
	}
	badAlgKey := &keys.PrivKey{Key: key.Key, Alg: "test"}

	badKey, _, err := keys.NewAsymmetricKeyPair(keys.ES256, 0)
	if err != nil {
		t.Errorf("Error generating test ec privkey: %v", err)
		return
	}
	badKey.Alg = key.Alg

	type args struct {
		claims *tokenauth.Claims
		key    *keys.PrivKey
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"missing key", args{validClaims, nil}, true},
		{"unsupported alg", args{validClaims, badAlgKey}, true},
		{"mismatched alg and key", args{validClaims, badKey}, true},
		{"success", args{validClaims, key}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tokenauth.GenerateSignedToken(tt.args.claims, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSignedToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTokenAuth_AuthorizeRequestPermissions(t *testing.T) {
	pubKey, err := testutils.GetSamplePubKey(keys.RS256)
	if err != nil {
		t.Errorf("Error getting sample pubkey: %v", err)
		return
	}

	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")
	testServiceReg := authservice.ServiceReg{ServiceID: authService.ServiceID, Host: authService.ServiceHost, PubKey: nil}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokwire.com", PubKey: pubKey}
	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	// Valid rokwire
	validClaims := getSampleValidClaims()

	path := "https://test.rokwire.com/example/test"
	type args struct {
		claims  *tokenauth.Claims
		request *http.Request
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid claims", args{validClaims, httptest.NewRequest(http.MethodGet, path, nil)}, false},
		{"return error on forbidden operation", args{validClaims, httptest.NewRequest(http.MethodPost, path, nil)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceRegLoader(authService, subscribed, serviceRegsValid, nil)

			tr, err := setupTestTokenAuth(authService, true, mockLoader)
			if err != nil || tr == nil {
				t.Errorf("Error initializing test token auth: %v", err)
				return
			}

			if err := tr.AuthorizeRequestPermissions(tt.args.claims, tt.args.request); (err != nil) != tt.wantErr {
				t.Errorf("TokenAuth.AuthorizeRequestPermissions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTokenAuth_AuthorizeRequestScope(t *testing.T) {
	pubKey, err := testutils.GetSamplePubKey(keys.RS256)
	if err != nil {
		t.Errorf("Error getting sample pubkey: %v", err)
		return
	}

	authService := testutils.SetupTestAuthService("test", "https://test.rokwire.com")
	testServiceReg := authservice.ServiceReg{ServiceID: authService.ServiceID, Host: authService.ServiceHost, PubKey: nil}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokwire.com", PubKey: pubKey}
	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	// Valid rokwire
	validClaims := getSampleValidClaims()
	validScopeClaims := getSampleValidClaims()
	validScopeClaims.Scope = "sample:test:read"
	invalidScopeClaims := getSampleValidClaims()
	invalidScopeClaims.Scope = "none"

	path := "https://test.rokwire.com/test"
	type args struct {
		claims  *tokenauth.Claims
		request *http.Request
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid scope all", args{validClaims, httptest.NewRequest(http.MethodGet, path, nil)}, false},
		{"valid scope exists in policy file", args{validScopeClaims, httptest.NewRequest(http.MethodGet, path, nil)}, false},
		{"return error on forbidden operation", args{validScopeClaims, httptest.NewRequest(http.MethodPut, path, nil)}, true},
		{"return error on invalid scope", args{invalidScopeClaims, httptest.NewRequest(http.MethodGet, path, nil)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceRegLoader(authService, subscribed, serviceRegsValid, nil)
			tr, err := setupTestTokenAuth(authService, true, mockLoader)
			if err != nil || tr == nil {
				t.Errorf("Error initializing test token auth: %v", err)
				return
			}

			if err := tr.AuthorizeRequestScope(tt.args.claims, tt.args.request); (err != nil) != tt.wantErr {
				t.Errorf("TokenAuth.AuthorizeRequestScope() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
