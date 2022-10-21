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
	"reflect"
	"testing"
)

func TestCasbinStringAuthorization_Any(t *testing.T) {
	type args struct {
		values []string
		object string
		action string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"test_permission_casbin_admin_get", args{[]string{"admin", "test"}, "/admin/test", "GET"}, false},
		{"test_permission_casbin_admin_post", args{[]string{"admin", "test"}, "/admin/test", "POST"}, false},
		{"test_permission_casbin_lite_admin", args{[]string{"lite_admin", "test"}, "/admin/test", "GET"}, false},
		{"test_permission_casbin_lite_admin_no_access", args{[]string{"lite_admin", "test"}, "/admin/test", "DELETE"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCasbinStringAuthorization("./test_permissions_authorization_policy.csv")
			if err := c.Any(tt.args.values, tt.args.object, tt.args.action); (err != nil) != tt.wantErr {
				t.Errorf("CasbinAuthorization.Any() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCasbinStringAuthorization_All(t *testing.T) {
	type args struct {
		values []string
		object string
		action string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"test_permission_casbin_admin_get", args{[]string{"admin"}, "/admin/test", "GET"}, false},
		{"test_permission_casbin_admin_fail", args{[]string{"admin", "test"}, "/admin/test", "GET"}, true},
		{"test_permission_casbin_lite_admin", args{[]string{"lite_admin", "test"}, "/admin/test", "GET"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCasbinStringAuthorization("./test_permissions_authorization_policy.csv")
			if err := c.All(tt.args.values, tt.args.object, tt.args.action); (err != nil) != tt.wantErr {
				t.Errorf("CasbinAuthorization.All() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCasbinScopeAuthorization_Any(t *testing.T) {
	type args struct {
		values []string
		object string
		action string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"return nil on matching read scope", args{[]string{"sample:test:read"}, "/test", "GET"}, false},
		{"return nil on matching write scope", args{[]string{"sample:test:write"}, "/test", "PUT"}, false},
		{"return nil on all scope", args{[]string{"all:all:all"}, "/test", "GET"}, false},
		{"return nil on all services scope", args{[]string{"all:test:read"}, "/test", "GET"}, false},
		{"return nil on all resources scope", args{[]string{"sample:all:read"}, "/test", "GET"}, false},
		{"return nil on all operations scope", args{[]string{"sample:test:all"}, "/test", "GET"}, false},
		{"return nil on global scope without policy entry", args{[]string{"all:all:all"}, "/test", "DELETE"}, false},
		{"return nil on service global scope without policy entry", args{[]string{"sample:all:all"}, "/test", "DELETE"}, false},
		{"return err on wrong scope", args{[]string{"sample:test:write"}, "/test", "GET"}, true},
		{"return err on missing scope", args{[]string{"sample:test:read", "test"}, "/test", "PUT"}, true},
		{"return err on all resources scope without policy entry", args{[]string{"sample:all:write"}, "/test", "DELETE"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCasbinScopeAuthorization("./test_scope_authorization_policy.csv", "sample")
			if err := c.Any(tt.args.values, tt.args.object, tt.args.action); (err != nil) != tt.wantErr {
				t.Errorf("CasbinScopeAuthorization.Any() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCasbinScopeAuthorization_All(t *testing.T) {
	type args struct {
		values []string
		object string
		action string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"test_scope_casbin", args{[]string{"sample:test:read"}, "/test", "GET"}, false},
		{"test_scope_casbin_no_access", args{[]string{"sample:test:read", "sample:test:write"}, "/test", "PUT"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCasbinScopeAuthorization("./test_scope_authorization_policy.csv", "sample")
			if err := c.All(tt.args.values, tt.args.object, tt.args.action); (err != nil) != tt.wantErr {
				t.Errorf("CasbinScopeAuthorization.All() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestScope_Grants(t *testing.T) {
	allAccount := Scope{ServiceID: "core", Resource: "account", Operation: "all"}
	getAccount := Scope{ServiceID: "core", Resource: "account", Operation: "get"}
	getAccountProfile := Scope{ServiceID: "core", Resource: "account.profile", Operation: "get"}
	getAccountProfileName := Scope{ServiceID: "core", Resource: "account.profile.name", Operation: "get"}
	getAll := Scope{ServiceID: "core", Resource: "all", Operation: "get"}
	allServiceAllAccount := Scope{ServiceID: "all", Resource: "account", Operation: "all"}
	otherServiceAllAccount := Scope{ServiceID: "other", Resource: "account", Operation: "all"}

	type args struct {
		want Scope
	}
	tests := []struct {
		name string
		have Scope
		args args
		want bool
	}{
		{"valid grant exact", getAccountProfile, args{getAccountProfile}, true},
		{"valid grant prefix", getAccountProfile, args{getAccountProfileName}, true},
		{"valid grant all ops", allAccount, args{getAccountProfile}, true},
		{"valid grant all services", allServiceAllAccount, args{getAccountProfile}, true},
		{"valid grant all resource", getAll, args{getAccountProfile}, true},
		{"invalid grant prefix", getAccountProfileName, args{getAccountProfile}, false},
		{"invalid grant op", getAccount, args{allAccount}, false},
		{"invalid grant service", otherServiceAllAccount, args{getAccountProfile}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.have.Grants(tt.args.want); got != tt.want {
				t.Errorf("Scope.Grants() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScope_IsSub(t *testing.T) {
	allAccount := Scope{ServiceID: "core", Resource: "account", Operation: "all"}
	getAccount := Scope{ServiceID: "core", Resource: "account", Operation: "get"}
	getAccountProfile := Scope{ServiceID: "core", Resource: "account.profile", Operation: "get"}
	allAccountProfile := Scope{ServiceID: "core", Resource: "account.profile", Operation: "all"}
	getAccountProfileName := Scope{ServiceID: "core", Resource: "account.profile.name", Operation: "get"}
	getAll := Scope{ServiceID: "core", Resource: "all", Operation: "get"}
	allServiceAllAccountProfile := Scope{ServiceID: "all", Resource: "account.profile", Operation: "all"}
	otherServiceAllAccountProfile := Scope{ServiceID: "other", Resource: "account.profile", Operation: "all"}

	type args struct {
		super Scope
	}
	tests := []struct {
		name string
		s    Scope
		args args
		want bool
	}{
		{"valid sub exact", getAccountProfile, args{getAccountProfile}, true},
		{"valid sub prefix", getAccountProfileName, args{getAccountProfile}, true},
		{"valid sub all ops", allAccountProfile, args{getAccount}, true},
		{"valid sub all services", allServiceAllAccountProfile, args{getAccount}, true},
		{"valid sub all resource", getAccount, args{getAll}, true},
		{"invalid sub prefix", getAccountProfile, args{getAccountProfileName}, false},
		{"invalid sub op", getAccount, args{allAccount}, false},
		{"invalid sub service", otherServiceAllAccountProfile, args{getAccount}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.s.IsSub(tt.args.super); got != tt.want {
				t.Errorf("Scope.IsSub() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScope_AssociatedResources(t *testing.T) {
	allAccount := Scope{ServiceID: "core", Resource: "account", Operation: "all"}
	getAccount := Scope{ServiceID: "core", Resource: "account", Operation: "get"}
	getAccountProfile := Scope{ServiceID: "core", Resource: "account.profile", Operation: "get"}
	updateAccountProfile := Scope{ServiceID: "core", Resource: "account.profile", Operation: "update"}
	allAccountProfile := Scope{ServiceID: "core", Resource: "account.profile", Operation: "all"}
	allAccountProfileName := Scope{ServiceID: "core", Resource: "account.profile.name", Operation: "all"}
	getAccountPreferences := Scope{ServiceID: "core", Resource: "account.preferences", Operation: "get"}
	getApplications := Scope{ServiceID: "core", Resource: "applications", Operation: "get"}
	allServiceAllAccountExternalIDs := Scope{ServiceID: "all", Resource: "account.external_ids", Operation: "all"}
	otherServiceAllAccountProfile := Scope{ServiceID: "other", Resource: "account.profile", Operation: "all"}
	getAll := Scope{ServiceID: "core", Resource: "all", Operation: "get"}

	type args struct {
		scopes       []Scope
		trimResource bool
	}
	tests := []struct {
		name          string
		s             Scope
		args          args
		want          bool
		wantResources []string
	}{
		{"all access exact", getAccount, args{[]Scope{getAccount, allAccountProfile}, true}, true, nil},
		{"all access super", getAccountProfile, args{[]Scope{allAccount}, false}, true, nil},
		{"all access global resource", getAccount, args{[]Scope{getAll}, false}, true, nil},
		{"valid subresources trim", getAccount, args{[]Scope{allAccountProfileName, getAccountPreferences, otherServiceAllAccountProfile, allServiceAllAccountExternalIDs}, true}, false, []string{"profile.name", "preferences", "external_ids"}},
		{"valid subresources no trim", getAccount, args{[]Scope{allAccountProfileName, getAccountPreferences, otherServiceAllAccountProfile, updateAccountProfile}, false}, false, []string{"account.profile.name", "account.preferences"}},
		{"no valid subresources", getAccount, args{[]Scope{otherServiceAllAccountProfile, getApplications, updateAccountProfile}, true}, false, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := tt.s.AssociatedResources(tt.args.scopes, tt.args.trimResource)
			if got != tt.want {
				t.Errorf("Scope.AssociatedResources() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.wantResources) {
				t.Errorf("Scope.AssociatedResources() got1 = %v, want %v", got1, tt.wantResources)
			}
		})
	}
}

func TestResourceAccessForScopes(t *testing.T) {
	allAccount := Scope{ServiceID: "core", Resource: "account", Operation: "all"}
	getAccount := Scope{ServiceID: "core", Resource: "account", Operation: "get"}
	updateAccount := Scope{ServiceID: "core", Resource: "account", Operation: "update"}
	getAccountProfile := Scope{ServiceID: "core", Resource: "account.profile", Operation: "get"}
	updateAccountProfile := Scope{ServiceID: "core", Resource: "account.profile", Operation: "update"}
	allAccountProfile := Scope{ServiceID: "core", Resource: "account.profile", Operation: "all"}
	allAccountProfileName := Scope{ServiceID: "core", Resource: "account.profile.name", Operation: "all"}
	getAccountPreferences := Scope{ServiceID: "core", Resource: "account.preferences", Operation: "get"}
	getApplications := Scope{ServiceID: "core", Resource: "applications", Operation: "get"}
	allServiceAllAccountExternalIDs := Scope{ServiceID: "all", Resource: "account.external_ids", Operation: "all"}
	otherServiceAllAccountProfile := Scope{ServiceID: "other", Resource: "account.profile", Operation: "all"}
	getAll := Scope{ServiceID: "core", Resource: "all", Operation: "get"}

	wantResources := []string{"profile.name", "profile.email", "preferences.privacy_level", "external_ids"}
	wantResourcesProfile := []string{"profile.name", "profile.email"}

	type args struct {
		scopes             []Scope
		minAllAccessScope  Scope
		requestedResources []string
	}
	tests := []struct {
		name       string
		args       args
		want       bool
		accessKeys []string
		wantErr    bool
	}{
		{"all access exact", args{[]Scope{getAccount, allAccountProfile}, getAccount, wantResources}, true, nil, false},
		{"all access super", args{[]Scope{allAccount}, getAccountProfile, wantResourcesProfile}, true, nil, false},
		{"all access global resource", args{[]Scope{getAll}, getAccount, wantResources}, true, nil, false},
		{"valid resource request",
			args{[]Scope{allAccountProfileName, getAccountPreferences, getAccountProfile, otherServiceAllAccountProfile, allServiceAllAccountExternalIDs, getApplications}, getAccount, wantResources},
			false, []string{"profile.name", "preferences", "profile", "external_ids"}, false},
		{"invalid resource request",
			args{[]Scope{allAccountProfileName, getAccountPreferences, otherServiceAllAccountProfile, updateAccountProfile, getApplications}, getAccount, wantResources},
			false, nil, true},
		{"invalid operation request",
			args{[]Scope{allAccountProfileName, getAccountPreferences, getAccountProfile, otherServiceAllAccountProfile, allServiceAllAccountExternalIDs, getApplications}, updateAccount, wantResources},
			false, nil, true},
		{"invalid no scopes",
			args{[]Scope{}, getAccount, wantResources},
			false, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := ResourceAccessForScopes(tt.args.scopes, tt.args.minAllAccessScope, tt.args.requestedResources)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResourceAccessForScopes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ResourceAccessForScopes() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.accessKeys) {
				t.Errorf("ResourceAccessForScopes() got1 = %v, want %v", got1, tt.accessKeys)
			}
		})
	}
}

func TestScopesFromStrings(t *testing.T) {
	getAccount := Scope{ServiceID: "core", Resource: "account", Operation: "get"}
	updateAccountProfile := Scope{ServiceID: "core", Resource: "account.profile", Operation: "update"}
	otherServiceAllAccountProfile := Scope{ServiceID: "other", Resource: "account.profile", Operation: "all"}
	getAll := Scope{ServiceID: "core", Resource: "all", Operation: "get"}

	type args struct {
		scopeStrings []string
		skipInvalid  bool
	}
	tests := []struct {
		name    string
		args    args
		want    []Scope
		wantErr bool
	}{
		{"valid scopes", args{[]string{"core:account:get", "core:account.profile:update", "other:account.profile:all", "core:all:get"}, false},
			[]Scope{getAccount, updateAccountProfile, otherServiceAllAccountProfile, getAll}, false},
		{"invalid scope ignore", args{[]string{"core:account:get", "core:account.profile", "other:account.profile:all", "core:all:get"}, true},
			[]Scope{getAccount, otherServiceAllAccountProfile, getAll}, false},
		{"invalid scope error", args{[]string{"core:account:get", "core:account.profile", "other:account.profile:all", "core:all:get"}, false},
			nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ScopesFromStrings(tt.args.scopeStrings, tt.args.skipInvalid)
			if (err != nil) != tt.wantErr {
				t.Errorf("ScopesFromStrings() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ScopesFromStrings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScopesToStrings(t *testing.T) {
	getAccount := Scope{ServiceID: "core", Resource: "account", Operation: "get"}
	updateAccountProfile := Scope{ServiceID: "core", Resource: "account.profile", Operation: "update"}
	otherServiceAllAccountProfile := Scope{ServiceID: "other", Resource: "account.profile", Operation: "all"}
	getAll := Scope{ServiceID: "core", Resource: "all", Operation: "get"}

	type args struct {
		scopes []Scope
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{"valid scopes", args{[]Scope{getAccount, updateAccountProfile, otherServiceAllAccountProfile, getAll}},
			[]string{"core:account:get", "core:account.profile:update", "other:account.profile:all", "core:all:get"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ScopesToStrings(tt.args.scopes); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ScopesToStrings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestListGrants(t *testing.T) {
	allAccount := Scope{ServiceID: "core", Resource: "account", Operation: "all"}
	getAccount := Scope{ServiceID: "core", Resource: "account", Operation: "get"}
	updateAccount := Scope{ServiceID: "core", Resource: "account", Operation: "update"}
	getAccountProfile := Scope{ServiceID: "core", Resource: "account.profile", Operation: "get"}
	allAccountProfile := Scope{ServiceID: "core", Resource: "account.profile", Operation: "all"}
	getApplications := Scope{ServiceID: "core", Resource: "applications", Operation: "get"}
	otherServiceAllAccountProfile := Scope{ServiceID: "other", Resource: "account.profile", Operation: "all"}
	getAll := Scope{ServiceID: "core", Resource: "all", Operation: "get"}

	type args struct {
		scopes []Scope
		want   Scope
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"valid grant exact", args{[]Scope{getAccount, allAccountProfile, getApplications}, getAccount}, true},
		{"valid grant super", args{[]Scope{allAccount, getApplications, otherServiceAllAccountProfile}, getAccountProfile}, true},
		{"valid grant global resource", args{[]Scope{getAll}, getAccount}, true},
		{"invalid grant other service", args{[]Scope{otherServiceAllAccountProfile, getApplications}, getAccount}, false},
		{"invalid grant operation", args{[]Scope{updateAccount, getApplications}, getAccount}, false},
		{"invalid grant resource", args{[]Scope{getApplications, getAccountProfile}, getAccount}, false},
		{"empty scopes", args{[]Scope{}, getApplications}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ListGrants(tt.args.scopes, tt.args.want); got != tt.want {
				t.Errorf("ListGrants() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestListGranted(t *testing.T) {
	allAccount := Scope{ServiceID: "core", Resource: "account", Operation: "all"}
	getAccount := Scope{ServiceID: "core", Resource: "account", Operation: "get"}
	updateAccount := Scope{ServiceID: "core", Resource: "account", Operation: "update"}
	getAccountProfile := Scope{ServiceID: "core", Resource: "account.profile", Operation: "get"}
	allAccountProfile := Scope{ServiceID: "core", Resource: "account.profile", Operation: "all"}
	getApplications := Scope{ServiceID: "core", Resource: "applications", Operation: "get"}
	otherServiceAllAccountProfile := Scope{ServiceID: "other", Resource: "account.profile", Operation: "all"}

	type args struct {
		scopes []Scope
		have   Scope
		all    bool
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"valid grant all", args{[]Scope{getAccount, updateAccount, allAccountProfile}, allAccount, true}, true},
		{"valid grant any", args{[]Scope{getAccountProfile, otherServiceAllAccountProfile, getApplications}, allAccount, false}, true},
		{"invalid grant all", args{[]Scope{updateAccount, getAccountProfile, allAccountProfile, getApplications}, allAccount, true}, false},
		{"invalid grant any", args{[]Scope{updateAccount, otherServiceAllAccountProfile}, getApplications, false}, false},
		{"empty scopes", args{[]Scope{}, getApplications, false}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ListGranted(tt.args.scopes, tt.args.have, tt.args.all); got != tt.want {
				t.Errorf("ListGranted() = %v, want %v", got, tt.want)
			}
		})
	}
}
