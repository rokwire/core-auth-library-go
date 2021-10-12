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
