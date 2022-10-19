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

package authorization

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/rokwire/core-auth-library-go/v2/authutils"
)

const (
	// ScopeAll represents all options of a scope component
	ScopeAll string = "all"
	// ScopeGlobal represents the global scope
	ScopeGlobal string = "all:all:all"
	//ScopeOperationGet indicates a scope may be used for a get operation
	ScopeOperationGet string = "get"
	//ScopeOperationCreate indicates a scope may be used for a create operation
	ScopeOperationCreate string = "create"
	//ScopeOperationUpdate indicates a scope may be used for a update operation
	ScopeOperationUpdate string = "update"
	//ScopeOperationDelete indicates a scope may be used for a delete operation
	ScopeOperationDelete string = "delete"
)

var (
	_, b, _, _ = runtime.Caller(0)
	basepath   = filepath.Dir(b)
)

// Authorization is a standard authorization interface that can be reused by various auth types.
type Authorization interface {
	Any(values []string, object string, action string) error
	All(values []string, object string, action string) error
}

// CasbinAuthorization is a Casbin implementation of the authorization interface.
type CasbinAuthorization struct {
	enforcer *casbin.Enforcer
}

// Any will validate that if the casbin enforcer gives access to one or more of the provided values
//
//	Returns nil on success and error on failure.
func (c *CasbinAuthorization) Any(values []string, object string, action string) error {
	for _, value := range values {
		if ok, _ := c.enforcer.Enforce(value, object, action); ok {
			return nil
		}
	}

	return fmt.Errorf("access control error: %v trying to apply %s operation for %s", values, action, object)
}

// All will validate that if the casbin enforcer gives access to all the provided values
//
//	Returns nil on success and error on failure.
func (c *CasbinAuthorization) All(values []string, object string, action string) error {
	for _, value := range values {
		if ok, _ := c.enforcer.Enforce(value, object, action); !ok {
			return fmt.Errorf("access control error: %s is trying to apply %s operation for %s", value, action, object)
		}
	}

	return nil
}

// NewCasbinStringAuthorization returns a new Casbin enforcer with the string model
func NewCasbinStringAuthorization(policyPath string) *CasbinAuthorization {
	enforcer, err := casbin.NewEnforcer(basepath+"/authorization_model_string.conf", policyPath)
	if err != nil {
		fmt.Printf("NewCasbinStringAuthorization() -> error: %s\n", err.Error())
	}

	return &CasbinAuthorization{enforcer}
}

// NewCasbinAuthorization returns a new Casbin enforcer
func NewCasbinAuthorization(modelPath string, policyPath string) *CasbinAuthorization {
	enforcer, err := casbin.NewEnforcer(modelPath, policyPath)
	if err != nil {
		fmt.Printf("NewCasbinAuthorization() -> error: %s\n", err.Error())
	}

	return &CasbinAuthorization{enforcer}
}

// CasbinScopeAuthorization is a Casbin implementation of the authorization interface for scope values.
type CasbinScopeAuthorization struct {
	enforcer  *casbin.Enforcer
	serviceID string
}

// Any will validate that if the Casbin enforcer gives access to one or more of the provided values
//
//	Returns nil on success and error on failure.
func (c *CasbinScopeAuthorization) Any(values []string, object string, action string) error {
	if CheckScopesGlobals(values, c.serviceID) {
		return nil
	}

	for _, value := range values {
		scope, err := ScopeFromString(value)
		if err != nil {
			continue
		}

		if !matchScopeField(scope.ServiceID, c.serviceID, false, true) {
			continue
		}

		if ok, _ := c.enforcer.Enforce(scope.Resource, scope.Operation, object, action); ok {
			return nil
		}
	}

	return fmt.Errorf("access control error: %v trying to apply %s operation for %s", values, action, object)
}

// All will validate that if the Casbin enforcer gives access to all the provided values
//
//	Returns nil on success and error on failure.
func (c *CasbinScopeAuthorization) All(values []string, object string, action string) error {
	for _, value := range values {
		reqErr := fmt.Errorf("access control error: %v is trying to apply %s operation for %s", value, action, object)
		scope, err := ScopeFromString(value)
		if err != nil {
			return reqErr
		}

		if scope.IsGlobal() || scope.IsServiceGlobal(c.serviceID) {
			continue
		}

		if !matchScopeField(scope.ServiceID, c.serviceID, false, true) {
			return reqErr
		}

		if ok, _ := c.enforcer.Enforce(scope.Resource, scope.Operation, object, action); !ok {
			return reqErr
		}
	}

	return nil
}

// NewCasbinScopeAuthorization returns a new casbin enforcer
func NewCasbinScopeAuthorization(policyPath string, serviceID string) *CasbinScopeAuthorization {
	enforcer, err := casbin.NewEnforcer(basepath+"/authorization_model_scope.conf", policyPath)
	if err != nil {
		fmt.Printf("NewCasbinScopeAuthorization() -> error: %s\n", err.Error())
	}

	return &CasbinScopeAuthorization{enforcer, serviceID}
}

// -------------------------- Scope --------------------------

// Scope represents a scope entity
type Scope struct {
	ServiceID string `json:"service_id" bson:"service_id"`
	Resource  string `json:"resource" bson:"resource"`
	Operation string `json:"operation" bson:"operation"`
}

// String converts the scope to the string representation
func (s *Scope) String() string {
	return fmt.Sprintf("%s:%s:%s", s.ServiceID, s.Resource, s.Operation)
}

// Match returns true if the scope matches the provided "other" scope
func (s *Scope) Match(other Scope) bool {
	if !matchScopeField(s.ServiceID, other.ServiceID, false, false) {
		return false
	}

	if !matchScopeField(s.Resource, other.Resource, true, false) {
		return false
	}

	if !matchScopeField(s.Operation, other.Operation, false, false) {
		return false
	}

	return true
}

// MatchSymmetric returns true if the scope matches the provided "other" scope
func (s *Scope) MatchSymmetric(other Scope) bool {
	if !matchScopeField(s.ServiceID, other.ServiceID, false, true) {
		return false
	}

	if !matchScopeField(s.Resource, other.Resource, false, true) {
		return false
	}

	if !matchScopeField(s.Operation, other.Operation, false, true) {
		return false
	}

	return true
}

// AssociatedScopes returns the subset of scopes that s grants access to or that grant access to s
//
//	Optionally trims the Resource of s from matched scopes' Resources
func (s *Scope) AssociatedScopes(scopes []Scope, trimResource bool) []Scope {
	relevant := make([]Scope, 0)
	for _, scope := range scopes {
		if s.Match(scope) || scope.Match(*s) {
			if trimResource {
				scope.Resource = strings.TrimPrefix(scope.Resource, s.Resource+".")
			}
			relevant = append(relevant, scope)
		}
	}
	return relevant
}

// IsGlobal returns true if the scope is the global scope
func (s *Scope) IsGlobal() bool {
	return s.ServiceID == ScopeAll && s.Resource == ScopeAll && s.Operation == ScopeAll
}

// IsServiceGlobal returns true if the scope is the service-level global scope
func (s *Scope) IsServiceGlobal(serviceID string) bool {
	return s.ServiceID == serviceID && s.Resource == ScopeAll && s.Operation == ScopeAll
}

// ScopeFromString creates a scope object from the string representation
func ScopeFromString(scope string) (*Scope, error) {
	comps := strings.Split(scope, ":")
	if len(comps) != 3 {
		return nil, fmt.Errorf("invalid scope string %s: format must be <service_id>:<resource>:<operation>", scope)
	}
	return &Scope{ServiceID: comps[0], Resource: comps[1], Operation: comps[2]}, nil
}

// ScopesFromStrings creates a list of scope objects from a list of string representations
func ScopesFromStrings(scopeStrings []string) ([]Scope, error) {
	scopes := make([]Scope, len(scopeStrings))
	for i, s := range scopeStrings {
		scope, err := ScopeFromString(s)
		if err != nil {
			return nil, err
		}
		scopes[i] = *scope
	}
	return scopes, nil
}

// ScopesToStrings creates a list of string representations from a list of scope objects
func ScopesToStrings(scopes []Scope) []string {
	scopeStrings := make([]string, len(scopes))
	for i, s := range scopes {
		scopeStrings[i] = s.String()
	}
	return scopeStrings
}

// MatchList returs true if any or all scopes match the provided "other" scope
func MatchList(scopes []Scope, other Scope, all bool) bool {
	if len(scopes) == 0 {
		return false
	}

	for _, s := range scopes {
		if s.Match(other) {
			if !all {
				return true
			}
		} else if all {
			return false
		}
	}
	return all
}

// ResourceAccessForScopes checks which resources a list of scopes grant access to
//
//	 Inputs:
//			scopes ([]Scope): list of scopes that have been granted
//			minAllAccessScope (Scope): minimum access scope that grants access to all requested resources
//			requestedResources: ([]string): list of data keys for which scope access should be checked
//	 Outputs:
//			allAccess (bool): whether any scope in scopes grants access to all requested resources
//			accessKeys ([]string): all data keys the provided scopes grant access to in minAllAccessScope context
//			err (error): returned if scopes do not grant access to all requested resources
func ResourceAccessForScopes(scopes []Scope, minAllAccessScope Scope, requestedResources []string) (bool, []string, error) {
	associatedScopes := minAllAccessScope.AssociatedScopes(scopes, true)
	for _, resource := range requestedResources {
		minResourceScope := Scope{ServiceID: minAllAccessScope.ServiceID, Resource: resource, Operation: minAllAccessScope.Operation}
		validRequest := false
		for _, scope := range associatedScopes {
			if scope.Match(minAllAccessScope) {
				return true, nil, nil
			}
			if scope.Match(minResourceScope) {
				validRequest = true
				break
			}
		}
		if !validRequest {
			return false, nil, fmt.Errorf("provided scopes do not grant access to resource %s", minResourceScope.Resource)
		}
	}

	accessKeys := make([]string, 0)
	for _, scope := range associatedScopes {
		accessKeys = append(accessKeys, scope.Resource)
	}
	return false, accessKeys, nil
}

// ScopeServiceGlobal returns the global scope
func ScopeServiceGlobal(serviceID string) string {
	return fmt.Sprintf("%s:%s:%s", serviceID, ScopeAll, ScopeAll)
}

// CheckScopesGlobals checks if the global or service global scope exists in the list of scope strings
func CheckScopesGlobals(scopes []string, serviceID string) bool {
	if len(scopes) == 0 {
		return false
	}

	// Grant access for global scope
	if authutils.ContainsString(scopes, ScopeGlobal) {
		return true
	}

	// Grant access if claims contain service-level global scope
	serviceAll := ScopeServiceGlobal(serviceID)
	return authutils.ContainsString(scopes, serviceAll)
}

func matchScopeField(x string, y string, matchPrefix bool, symmetric bool) bool {
	if x == y || (!symmetric && matchPrefix && strings.HasPrefix(y, x)) || x == ScopeAll || (symmetric && y == ScopeAll) {
		return true
	}
	return false
}
