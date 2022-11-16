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

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

// Handler is an interface for token auth handlers
type Handler interface {
	Check(req *http.Request) (int, *Claims, error)
	GetTokenAuth() *TokenAuth
}

// Handlers represents the standard token auth handlers
type Handlers struct {
	Standard      Handler
	Permissions   PermissionsHandler
	User          UserHandler
	Authenticated AuthenticatedHandler
}

// NewHandlers creates new token auth handlers
func NewHandlers(auth Handler) Handlers {
	permissionsAuth := NewPermissionsHandler(auth)
	userAuth := NewUserHandler(auth)
	authenticatedAuth := NewAuthenticatedHandler(userAuth)

	authWrappers := Handlers{Standard: auth, Permissions: permissionsAuth, User: userAuth, Authenticated: authenticatedAuth}
	return authWrappers
}

// StandardHandler entity
// This enforces that the token is valid
type StandardHandler struct {
	tokenAuth TokenAuth
}

// Check checks the token in the provided request
func (a StandardHandler) Check(req *http.Request) (int, *Claims, error) {
	claims, err := a.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, nil, errors.WrapErrorAction(logutils.ActionValidate, logutils.TypeToken, nil, err)
	}

	return http.StatusOK, claims, nil
}

// GetTokenAuth exposes the TokenAuth for the handler
func (a StandardHandler) GetTokenAuth() *TokenAuth {
	return &a.tokenAuth
}

// NewStandardHandler creates a new StandardHandler
func NewStandardHandler(tokenAuth TokenAuth) StandardHandler {
	return StandardHandler{tokenAuth: tokenAuth}
}

// ScopeHandler entity
// This enforces that the token has scopes matching the policy
type ScopeHandler struct {
	tokenAuth TokenAuth
}

// Check checks the token in the provided request
func (a ScopeHandler) Check(req *http.Request) (int, *Claims, error) {
	claims, err := a.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, nil, errors.WrapErrorAction(logutils.ActionValidate, logutils.TypeToken, nil, err)
	}

	err = a.tokenAuth.AuthorizeRequestScope(claims, req)
	if err != nil {
		return http.StatusForbidden, nil, errors.WrapErrorAction(logutils.ActionValidate, logutils.TypeScope, nil, err)
	}

	return http.StatusOK, claims, nil
}

// GetTokenAuth exposes the TokenAuth for the handler
func (a ScopeHandler) GetTokenAuth() *TokenAuth {
	return &a.tokenAuth
}

// NewScopeHandler creates a new ScopeHandler
func NewScopeHandler(tokenAuth TokenAuth) ScopeHandler {
	return ScopeHandler{tokenAuth: tokenAuth}
}

// PermissionsHandler entity
// This enforces that the token has permissions matching the policy
type PermissionsHandler struct {
	auth Handler
}

// Check checks the token in the provided request
func (a PermissionsHandler) Check(req *http.Request) (int, *Claims, error) {
	status, claims, err := a.auth.Check(req)
	if err != nil || claims == nil {
		return status, claims, err
	}

	err = a.auth.GetTokenAuth().AuthorizeRequestPermissions(claims, req)
	if err != nil {
		return http.StatusForbidden, nil, errors.WrapErrorAction(logutils.ActionValidate, logutils.TypePermission, nil, err)
	}

	return status, claims, err
}

// GetTokenAuth exposes the TokenAuth for the handler
func (a PermissionsHandler) GetTokenAuth() *TokenAuth {
	return a.auth.GetTokenAuth()
}

// NewPermissionsHandler creates a new PermissionsHandler
func NewPermissionsHandler(auth Handler) PermissionsHandler {
	return PermissionsHandler{auth: auth}
}

// UserHandler entity
// This enforces that the token is not anonymous
type UserHandler struct {
	auth Handler
}

// Check checks the token in the provided request
func (a UserHandler) Check(req *http.Request) (int, *Claims, error) {
	status, claims, err := a.auth.Check(req)
	if err != nil || claims == nil {
		return status, claims, err
	}

	if claims.Anonymous {
		return http.StatusForbidden, nil, errors.New("token must not be anonymous")
	}

	return status, claims, err
}

// GetTokenAuth exposes the TokenAuth for the handler
func (a UserHandler) GetTokenAuth() *TokenAuth {
	return a.auth.GetTokenAuth()
}

// NewUserHandler creates a new UserHandler
func NewUserHandler(auth Handler) UserHandler {
	return UserHandler{auth: auth}
}

// AuthenticatedHandler entity
// This enforces that the token was the result of direct user authentication. This should be used to protect sensitive account settings
type AuthenticatedHandler struct {
	userAuth UserHandler
}

// Check checks the token in the provided request
func (a AuthenticatedHandler) Check(req *http.Request) (int, *Claims, error) {
	status, claims, err := a.userAuth.Check(req)
	if err != nil || claims == nil {
		return status, claims, err
	}

	if !claims.Authenticated {
		return http.StatusForbidden, nil, errors.New("user must login again")
	}

	return status, claims, err
}

// GetTokenAuth exposes the TokenAuth for the handler
func (a AuthenticatedHandler) GetTokenAuth() *TokenAuth {
	return a.userAuth.GetTokenAuth()
}

// NewAuthenticatedHandler creates a new AuthenticatedHandler
func NewAuthenticatedHandler(userAuth UserHandler) AuthenticatedHandler {
	return AuthenticatedHandler{userAuth: userAuth}
}
