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

package tokenauth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/rokwire/core-auth-library-go/v2/authorization"
	"github.com/rokwire/core-auth-library-go/v2/authservice"
	"github.com/rokwire/core-auth-library-go/v2/authutils"
	"github.com/rokwire/core-auth-library-go/v2/keys"
)

const (
	// AudRokwire represents the ROKWIRE audience
	AudRokwire string = "rokwire"
)

// Claims represents the standard claims included in access tokens
type Claims struct {
	// Required Standard Claims: sub, aud, exp, iat
	jwt.StandardClaims
	OrgID         string `json:"org_id" validate:"required"`    // Organization ID
	AppID         string `json:"app_id"`                        // Application ID
	SessionID     string `json:"session_id"`                    // Session ID
	Purpose       string `json:"purpose" validate:"required"`   // Token purpose (eg. access...)
	AuthType      string `json:"auth_type" validate:"required"` // Authentication method (eg. email, phone...)
	Permissions   string `json:"permissions"`                   // Granted permissions
	Scope         string `json:"scope"`                         // Granted scope
	Anonymous     bool   `json:"anonymous"`                     // Is the user anonymous?
	Authenticated bool   `json:"authenticated"`                 // Did the user authenticate? (false on refresh)
	Service       bool   `json:"service"`                       // Is this token for a service account?
	FirstParty    bool   `json:"first_party"`                   // Is this token used by a first party service (eg. ROKWIRE building block)?
	Admin         bool   `json:"admin"`                         // Is this token for an admin?
	System        bool   `json:"system"`                        // Is this token for a system admin?

	// User Data: DO NOT USE AS IDENTIFIER OR SHARE WITH THIRD-PARTY SERVICES
	Name        string            `json:"name,omitempty"`         // User full name
	Email       string            `json:"email,omitempty"`        // User email address
	Phone       string            `json:"phone,omitempty"`        // User phone number
	ExternalIDs map[string]string `json:"external_ids,omitempty"` // External user identifiers for use in external integrations

	//TODO: Once the new user ID scheme has been adopted across all services these claims should be removed
	UID string `json:"uid,omitempty"` // Unique user identifier for specified "auth_type"
}

// AppOrg returns the AppOrgPair for the claims
func (c Claims) AppOrg() authservice.AppOrgPair {
	return authservice.AppOrgPair{AppID: c.AppID, OrgID: c.OrgID}
}

// Scopes returns the scopes from the claims as a slice
func (c Claims) Scopes() []authorization.Scope {
	scopes, _ := authorization.ScopesFromStrings(strings.Split(c.Scope, " "), true)
	return scopes
}

// CanAccess returns an error if the claims do not grant access to a resource with the given appID, orgId, and system status
func (c Claims) CanAccess(appID string, orgID string, system bool) error {
	// forbidden if not system admin and a system resource
	if !c.System && system {
		return errors.New("non-system admin access is forbidden")
	}

	if c.Service {
		// if a service, check if claimed appID, orgID match a pair granting access to resource appID, orgID
		for _, pair := range authservice.GetAccessPairs(appID, orgID) {
			if pair.AppID == c.AppID && pair.OrgID == c.OrgID {
				return nil
			}
		}

		return fmt.Errorf("access forbidden for app_id %s, org_id %s", c.AppID, c.OrgID)
	}

	if appID != c.AppID && appID != authutils.AllApps {
		return fmt.Errorf("access to appID %s is forbidden", appID)
	}

	if orgID != c.OrgID && !(c.System && orgID == authutils.AllOrgs) {
		return fmt.Errorf("access to orgID %s is forbidden", orgID)
	}

	return nil
}

// TokenAuth contains configurations and helper functions required to validate tokens
type TokenAuth struct {
	serviceRegManager   *authservice.ServiceRegManager
	acceptRokwireTokens bool

	permissionAuth authorization.Authorization
	scopeAuth      authorization.Authorization

	blacklist     []string
	blacklistLock *sync.RWMutex
	blacklistSize int
}

// CheckToken validates the provided token and returns the token claims
func (t *TokenAuth) CheckToken(token string, purpose string) (*Claims, error) {
	for i := len(t.blacklist) - 1; i >= 0; i-- {
		if token == t.blacklist[i] {
			return nil, fmt.Errorf("known invalid token")
		}
	}
	authServiceReg, err := t.serviceRegManager.GetServiceRegWithPubKey("auth")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve auth service pub key: %v", err)
	}

	parsedToken, tokenErr := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return authServiceReg.PubKey.Key, nil
	})
	if parsedToken == nil {
		return nil, errors.New("failed to parse token")
	}

	claims, ok := parsedToken.Claims.(*Claims)
	if !ok {
		return nil, errors.New("failed to parse token claims")
	}

	// Check token claims
	if claims.Subject == "" {
		return nil, errors.New("token sub missing")
	}
	if claims.ExpiresAt == 0 {
		return nil, errors.New("token exp missing")
	}
	if claims.IssuedAt == 0 {
		return nil, errors.New("token iat missing")
	}
	if claims.OrgID == "" {
		return nil, errors.New("token org_id missing")
	}
	if claims.AuthType == "" {
		return nil, errors.New("token auth_type missing")
	}
	if claims.Issuer != authServiceReg.Host {
		return nil, fmt.Errorf("token iss (%s) does not match %s", claims.Issuer, authServiceReg.Host)
	}
	if claims.Purpose != purpose {
		return nil, fmt.Errorf("token purpose (%s) does not match %s", claims.Purpose, purpose)
	}

	aud := strings.Split(claims.Audience, ",")
	if !(authutils.ContainsString(aud, t.serviceRegManager.AuthService.ServiceID) || (t.acceptRokwireTokens && authutils.ContainsString(aud, AudRokwire))) {
		acceptAuds := t.serviceRegManager.AuthService.ServiceID
		if t.acceptRokwireTokens {
			acceptAuds += " or " + AudRokwire
		}

		return nil, fmt.Errorf("token aud (%s) does not match %s", claims.Audience, acceptAuds)
	}

	// Check token headers
	alg, _ := parsedToken.Header["alg"].(string)
	if alg != authServiceReg.PubKey.Alg {
		return nil, fmt.Errorf("token alg (%s) does not match %s", alg, authServiceReg.PubKey.Alg)
	}
	typ, _ := parsedToken.Header["typ"].(string)
	if typ != "JWT" {
		return nil, fmt.Errorf("token typ (%s) does not match JWT", typ)
	}
	kid, _ := parsedToken.Header["kid"].(string)
	if kid != authServiceReg.PubKey.KeyID {
		if !parsedToken.Valid {
			if claims.ExpiresAt > time.Now().Unix() {
				refreshed, refreshErr := t.serviceRegManager.CheckForRefresh()
				if refreshErr != nil {
					return nil, fmt.Errorf("initial token check returned invalid, error on retry: %v", refreshErr)
				}
				if refreshed {
					return t.retryCheckToken(token, purpose)
				}
				return nil, fmt.Errorf("token invalid: %v", tokenErr)
			}
			return nil, fmt.Errorf("token is expired %d", claims.ExpiresAt)
		}
		return nil, fmt.Errorf("token has valid signature but invalid kid %s", kid)
	}

	if !parsedToken.Valid {
		return nil, fmt.Errorf("token invalid: %v", tokenErr)
	}

	return claims, nil
}

func (t *TokenAuth) retryCheckToken(token string, purpose string) (*Claims, error) {
	retryClaims, retryErr := t.CheckToken(token, purpose)
	if retryErr != nil {
		t.blacklistLock.Lock()
		if len(t.blacklist) >= t.blacklistSize {
			t.blacklist = t.blacklist[1:]
		}
		t.blacklist = append(t.blacklist, token)
		t.blacklistLock.Unlock()
	}
	return retryClaims, retryErr
}

// CheckRequestToken is a convenience function which retrieves and checks the access token included in a request and returns the claims
// Access tokens must be provided as a Bearer token in the "Authorization" header
func (t *TokenAuth) CheckRequestToken(r *http.Request) (*Claims, error) {
	accessToken, err := GetAccessToken(r)
	if err != nil {
		return nil, fmt.Errorf("error getting access token: %v", err)
	}

	accessClaims, err := t.CheckToken(accessToken, "access")
	if err != nil {
		return nil, fmt.Errorf("error validating access token: %v", err)
	}

	return accessClaims, nil
}

// ValidatePermissionsClaim will validate that the provided token claims contain one or more of the required permissions
//
//	Returns nil on success and error on failure.
func (t *TokenAuth) ValidatePermissionsClaim(claims *Claims, requiredPermissions []string) error {
	if len(requiredPermissions) == 0 {
		return nil
	}

	if claims.Permissions == "" {
		return errors.New("permissions claim empty")
	}

	// Grant access if claims contain any of the required permissions
	permissions := strings.Split(claims.Permissions, ",")
	for _, v := range requiredPermissions {
		if authutils.ContainsString(permissions, v) {
			return nil
		}
	}

	return fmt.Errorf("required permissions not found: required %v, found %s", requiredPermissions, claims.Permissions)
}

// AuthorizeRequestPermissions will authorize the request if the permissions claim passes the permissionsAuth
//
//	Returns nil on success and error on failure.
func (t *TokenAuth) AuthorizeRequestPermissions(claims *Claims, request *http.Request) error {
	if t.permissionAuth == nil {
		return errors.New("permission authorization policy not configured")
	}

	if claims == nil || claims.Permissions == "" {
		return errors.New("permissions claim empty")
	}

	permissions := strings.Split(claims.Permissions, ",")
	object := request.URL.Path
	action := request.Method

	return t.permissionAuth.Any(permissions, object, action)
}

// ValidateScopeClaim will validate that the provided token claims contain the required scope
//
//	If an empty required scope is provided, the claims must contain a valid global scope such as 'all:all:all' or '{service}:all:all'
//	Returns nil on success and error on failure.
func (t *TokenAuth) ValidateScopeClaim(claims *Claims, requiredScope string) error {
	if claims == nil || claims.Scope == "" {
		return errors.New("scope claim empty")
	}

	scopes := strings.Split(claims.Scope, " ")
	if authorization.CheckScopesGlobals(scopes, t.serviceRegManager.AuthService.ServiceID) {
		return nil
	}

	required, err := authorization.ScopeFromString(requiredScope)
	if err != nil {
		return fmt.Errorf("invalid required scope: %v", err)
	}

	for _, scopeString := range scopes {
		scope, err := authorization.ScopeFromString(scopeString)
		if err != nil {
			continue
		}

		if scope.Grants(*required) {
			return nil
		}
	}

	return fmt.Errorf("required scope not found: required %s, found %s", requiredScope, claims.Scope)
}

// AuthorizeRequestScope will authorize the request if the scope claim passes the scopeAuth
//
//	Returns nil on success and error on failure.
func (t *TokenAuth) AuthorizeRequestScope(claims *Claims, request *http.Request) error {
	if t.scopeAuth == nil {
		return errors.New("scope authorization policy not configured")
	}

	if claims == nil || claims.Scope == "" {
		return errors.New("scope claim empty")
	}

	scopes := strings.Split(claims.Scope, " ")
	object := request.URL.Path
	action := request.Method

	return t.scopeAuth.Any(scopes, object, action)
}

// SetBlacklistSize sets the maximum size of the token blacklist queue
//
//	The default value is 1024
func (t *TokenAuth) SetBlacklistSize(size int) {
	t.blacklistLock.Lock()
	t.blacklistSize = size
	t.blacklistLock.Unlock()
}

// NewTokenAuth creates and configures a new TokenAuth instance
// authorization maybe nil if performing manual authorization
func NewTokenAuth(acceptRokwireTokens bool, serviceRegManager *authservice.ServiceRegManager, permissionAuth authorization.Authorization, scopeAuth authorization.Authorization) (*TokenAuth, error) {
	if serviceRegManager == nil {
		return nil, errors.New("service registration manager is missing")
	}

	serviceRegManager.SubscribeServices([]string{"auth"}, true)

	blLock := &sync.RWMutex{}
	bl := []string{}

	return &TokenAuth{acceptRokwireTokens: acceptRokwireTokens, serviceRegManager: serviceRegManager, permissionAuth: permissionAuth, scopeAuth: scopeAuth, blacklistLock: blLock, blacklist: bl, blacklistSize: 1024}, nil
}

// -------------------------- Helper Functions --------------------------

// GetAccessToken retrieves an access token from the request headers
//
// Access tokens must be provided as a Bearer token in the "Authorization" header
func GetAccessToken(r *http.Request) (string, error) {
	authorizationHeader := r.Header.Get("Authorization")
	if authorizationHeader == "" {
		return "", errors.New("missing access token")
	}

	splitAuthorization := strings.Fields(authorizationHeader)
	if len(splitAuthorization) != 2 {
		return "", errors.New("invalid authorization header format")
	}
	if strings.ToLower(splitAuthorization[0]) != "bearer" {
		return "", errors.New("authorization header missing bearer token")
	}
	idToken := splitAuthorization[1]

	return idToken, nil
}

// GenerateSignedToken generates and signs a new JWT with the given claims using key
func GenerateSignedToken(claims *Claims, key *keys.PrivKey) (string, error) {
	if key == nil {
		return "", errors.New("private key is missing")
	}

	sigMethod := jwt.GetSigningMethod(key.Alg)
	if sigMethod == nil {
		return "", fmt.Errorf("unsupported signing method for %s", key.Alg)
	}
	token := jwt.NewWithClaims(sigMethod, claims)
	if key.PubKey == nil {
		err := key.ComputePubKey()
		if err != nil {
			return "", fmt.Errorf("error computing pubkey: %v", err)
		}
	}

	token.Header["kid"] = key.PubKey.KeyID
	return token.SignedString(key.Key)
}
