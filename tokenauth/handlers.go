// Copyright 2022 Board of Trustees of the University of Illinois
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
	"net/http"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	typeCheckPermission logutils.MessageActionType = "checking permission"
	typeCheckScope      logutils.MessageActionType = "checking scope"
)

// TokenAuthHandler is an interface for token auth handlers
type TokenAuthHandler interface {
	Check(req *http.Request) (int, *Claims, error)
	GetTokenAuth() *TokenAuth
}

// TokenAuthHandlers represents the standard token auth handlers
type TokenAuthHandlers struct {
	Standard      TokenAuthHandler
	Permissions   PermissionsTokenAuthHandler
	User          UserTokenAuthHandler
	Authenticated AuthenticatedTokenAuthHandler
}

// NewTokenAuthHandlers creates new auth handlers for a given
func NewTokenAuthHandlers(auth TokenAuthHandler) TokenAuthHandlers {
	permissionsAuth := NewPermissionsAuth(auth)
	userAuth := NewUserAuth(auth)
	authenticatedAuth := NewAuthenticatedAuth(userAuth)

	authWrappers := TokenAuthHandlers{Standard: auth, Permissions: permissionsAuth, User: userAuth, Authenticated: authenticatedAuth}
	return authWrappers
}

// StandardAuth entity
// This enforces that the user has a valid token
type StandardTokenAuthHandler struct {
	tokenAuth TokenAuth
}

func (a StandardTokenAuthHandler) Check(req *http.Request) (int, *Claims, error) {
	claims, err := a.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, nil, errors.WrapErrorAction(logutils.ActionValidate, logutils.TypeToken, nil, err)
	}

	return http.StatusOK, claims, nil
}

func (a StandardTokenAuthHandler) GetTokenAuth() *TokenAuth {
	return &a.tokenAuth
}

func NewStandardTokenAuthHandler(tokenAuth TokenAuth) StandardTokenAuthHandler {
	return StandardTokenAuthHandler{tokenAuth: tokenAuth}
}

// ScopeTokenAuthHandler entity
// This enforces that the token has scopes matching the policy
type ScopeTokenAuthHandler struct {
	tokenAuth TokenAuth
}

func (a ScopeTokenAuthHandler) Check(req *http.Request) (int, *Claims, error) {
	claims, err := a.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, nil, errors.WrapErrorAction(logutils.ActionValidate, logutils.TypeToken, nil, err)
	}

	err = a.tokenAuth.AuthorizeRequestScope(claims, req)
	if err != nil {
		return http.StatusForbidden, nil, errors.WrapErrorAction(typeCheckScope, logutils.TypeRequest, nil, err)
	}

	return http.StatusOK, claims, nil
}

func (a ScopeTokenAuthHandler) GetTokenAuth() *TokenAuth {
	return &a.tokenAuth
}

func NewScopeTokenAuthHandler(tokenAuth TokenAuth) ScopeTokenAuthHandler {
	return ScopeTokenAuthHandler{tokenAuth: tokenAuth}
}

// PermissionsAuth entity
// This enforces that the token has permissions matching the policy
type PermissionsTokenAuthHandler struct {
	auth TokenAuthHandler
}

func (a PermissionsTokenAuthHandler) Check(req *http.Request) (int, *Claims, error) {
	status, claims, err := a.auth.Check(req)
	if err != nil || claims == nil {
		return status, claims, err
	}

	err = a.auth.GetTokenAuth().AuthorizeRequestPermissions(claims, req)
	if err != nil {
		return http.StatusForbidden, nil, errors.WrapErrorAction(typeCheckPermission, logutils.TypeRequest, nil, err)
	}

	return status, claims, err
}

func (a PermissionsTokenAuthHandler) GetTokenAuth() *TokenAuth {
	return a.auth.GetTokenAuth()
}

func NewPermissionsAuth(auth TokenAuthHandler) PermissionsTokenAuthHandler {
	return PermissionsTokenAuthHandler{auth: auth}
}

// UserAuth entity
// This enforces that the token is not anonymous
type UserTokenAuthHandler struct {
	auth TokenAuthHandler
}

func (a UserTokenAuthHandler) Check(req *http.Request) (int, *Claims, error) {
	status, claims, err := a.auth.Check(req)
	if err != nil || claims == nil {
		return status, claims, err
	}

	if claims.Anonymous {
		return http.StatusForbidden, nil, errors.New("token must not be anonymous")
	}

	return status, claims, err
}

func (a UserTokenAuthHandler) GetTokenAuth() *TokenAuth {
	return a.auth.GetTokenAuth()
}

func NewUserAuth(auth TokenAuthHandler) UserTokenAuthHandler {
	return UserTokenAuthHandler{auth: auth}
}

// AuthenticatedAuth entity
// This enforces that the token was the result of direct user authentication. This should be used to protect sensitive account settings
type AuthenticatedTokenAuthHandler struct {
	userAuth UserTokenAuthHandler
}

func (auth AuthenticatedTokenAuthHandler) Check(req *http.Request) (int, *Claims, error) {
	status, claims, err := auth.userAuth.Check(req)
	if err != nil || claims == nil {
		return status, claims, err
	}

	if !claims.Authenticated {
		return http.StatusForbidden, nil, errors.New("user must login again")
	}

	return status, claims, err
}

func (a AuthenticatedTokenAuthHandler) GetTokenAuth() *TokenAuth {
	return a.userAuth.GetTokenAuth()
}

func NewAuthenticatedAuth(userAuth UserTokenAuthHandler) AuthenticatedTokenAuthHandler {
	return AuthenticatedTokenAuthHandler{userAuth: userAuth}
}
