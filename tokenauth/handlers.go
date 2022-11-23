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
	tokenAuth   TokenAuth
	claimsCheck func(*Claims, *http.Request) (int, error)
}

// Check checks the token in the provided request
func (h StandardHandler) Check(req *http.Request) (int, *Claims, error) {
	claims, err := h.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, nil, errors.WrapErrorAction(logutils.ActionValidate, logutils.TypeToken, nil, err)
	}

	status := http.StatusOK
	if h.claimsCheck != nil {
		status, err = h.claimsCheck(claims, req)
		if err != nil {
			return status, nil, err
		}
	}

	return status, claims, nil
}

// GetTokenAuth exposes the TokenAuth for the handler
func (h StandardHandler) GetTokenAuth() *TokenAuth {
	return &h.tokenAuth
}

// NewStandardHandler creates a new StandardHandler
func NewStandardHandler(tokenAuth TokenAuth, claimsCheck func(*Claims, *http.Request) (int, error)) StandardHandler {
	return StandardHandler{tokenAuth: tokenAuth, claimsCheck: claimsCheck}
}

// NewScopeHandler creates a new StandardHandler that checks scopes
func NewScopeHandler(tokenAuth TokenAuth, claimsCheck func(*Claims, *http.Request) (int, error)) StandardHandler {
	check := func(claims *Claims, req *http.Request) (int, error) {
		status := http.StatusOK
		var err error
		if claimsCheck != nil {
			status, err = claimsCheck(claims, req)
			if err != nil {
				return status, err
			}
		}

		err = tokenAuth.AuthorizeRequestScope(claims, req)
		if err != nil {
			return http.StatusForbidden, errors.WrapErrorAction(logutils.ActionValidate, logutils.TypeScope, nil, err)
		}

		return status, nil
	}

	return NewStandardHandler(tokenAuth, check)
}

// PermissionsHandler entity
// This enforces that the token has permissions matching the policy
type PermissionsHandler struct {
	auth Handler
}

// Check checks the token in the provided request
func (h PermissionsHandler) Check(req *http.Request) (int, *Claims, error) {
	status, claims, err := h.auth.Check(req)
	if err != nil || claims == nil {
		return status, claims, err
	}

	err = h.auth.GetTokenAuth().AuthorizeRequestPermissions(claims, req)
	if err != nil {
		return http.StatusForbidden, nil, errors.WrapErrorAction(logutils.ActionValidate, logutils.TypePermission, nil, err)
	}

	return status, claims, err
}

// GetTokenAuth exposes the TokenAuth for the handler
func (h PermissionsHandler) GetTokenAuth() *TokenAuth {
	return h.auth.GetTokenAuth()
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
func (h UserHandler) Check(req *http.Request) (int, *Claims, error) {
	status, claims, err := h.auth.Check(req)
	if err != nil || claims == nil {
		return status, claims, err
	}

	if claims.Anonymous {
		return http.StatusForbidden, nil, errors.New("token must not be anonymous")
	}

	return status, claims, err
}

// GetTokenAuth exposes the TokenAuth for the handler
func (h UserHandler) GetTokenAuth() *TokenAuth {
	return h.auth.GetTokenAuth()
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
func (h AuthenticatedHandler) Check(req *http.Request) (int, *Claims, error) {
	status, claims, err := h.userAuth.Check(req)
	if err != nil || claims == nil {
		return status, claims, err
	}

	if !claims.Authenticated {
		return http.StatusForbidden, nil, errors.New("user must login again")
	}

	return status, claims, err
}

// GetTokenAuth exposes the TokenAuth for the handler
func (h AuthenticatedHandler) GetTokenAuth() *TokenAuth {
	return h.userAuth.GetTokenAuth()
}

// NewAuthenticatedHandler creates a new AuthenticatedHandler
func NewAuthenticatedHandler(userAuth UserHandler) AuthenticatedHandler {
	return AuthenticatedHandler{userAuth: userAuth}
}
