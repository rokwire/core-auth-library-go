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
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/rokwire/core-auth-library-go/authservice"
	"github.com/rokwire/core-auth-library-go/authutils"
	"github.com/rokwire/core-auth-library-go/internal/testutils"
)

func setupPubKeyFromPem(pem string) *authservice.PubKey {
	return &authservice.PubKey{KeyPem: pem, Alg: "RS256"}
}

func setupSampleServiceRegSubscriptions() *authservice.ServiceRegSubscriptions {
	return authservice.NewServiceRegSubscriptions([]string{"auth", "test"})
}

func TestServiceRegManager_GetServiceReg(t *testing.T) {
	authPubKey := testutils.GetSamplePubKey()
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
	authPubKey := testutils.GetSamplePubKey()
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
	wrongKeyPem := `-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEA2RftabNugtaQNtJzLeKS5sy3RUH5nmP2ul0ULm/iiv2n7dQZyczk
/456/8BXRsoObDAAZBGf2JjpDItJa/v3d2qyPCwEYRUnzvnNdOV74IIraR/msa2W
NksvHRBujetp9spfdfLvULm8J7sPmCnoRR9icajSye9qNcjx7uuBzTosQmefpIWw
yOV2q/+dAQKe4ADkLMFRzMBt6z9mOZk+7AxLL0dxCDBufqStUpskPzDFj5VjZ8Pm
MBViPm2VHlXc2oyhTpvt86rdZ19jXTl+WdFGZO+o0Wo08YzUoCot7MZ1LwiHLXF/
Rs/dqTeDxXncn8SEReSzr03lUY8HdyRceflQdJjxZA3KP4BZ8Bqb0mhN3gXLIdFv
j/2oLs8yGD2fd7GxTVu+cnHRrZleYvsOWHPNBDW3lwHZr2cdPE60oIx9culbZwl4
UESf0lL26Qupn0Ha2tbF25cwEBM4ZvO41bKeqozXFOLRXYn4r2ZDahcRfHjF04kp
LrSVbitnfQD1AgMBAAE=
-----END RSA PUBLIC KEY-----`
	pubKey := testutils.GetSamplePubKey()
	wrongKey := setupPubKeyFromPem(wrongKeyPem)

	wrongKey.LoadKeyFromPem()
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

	privKey := testutils.GetSamplePrivKey()

	type args struct {
		privKey *rsa.PrivateKey
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

func TestPubKey_LoadKeyFromPem(t *testing.T) {
	tests := []struct {
		name    string
		p       *authservice.PubKey
		wantErr bool
		wantKey *rsa.PublicKey
		wantKid string
	}{
		{"return nil and set Key, Kid property on valid pem", setupPubKeyFromPem(testutils.GetSamplePubKeyPem()), false, testutils.GetSamplePubKey().Key, testutils.GetSamplePubKeyFingerprint()},
		{"return error on invalid pem", setupPubKeyFromPem("test"), true, nil, ""},
		{"return error on nil pubkey", nil, true, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.p.LoadKeyFromPem(); (err != nil) != tt.wantErr {
				t.Errorf("PubKey.LoadKeyFromPem() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantKey == nil {
				if tt.p != nil && tt.p.Key != nil {
					t.Errorf("PubKey.LoadKeyFromPem() key = %v, want nil", tt.p.Key)
				}
			} else {
				if !tt.p.Key.Equal(tt.wantKey) {
					t.Errorf("PubKey.LoadKeyFromPem() key = %v, want %v", tt.p.Key, tt.wantKey)
				}
			}
			if tt.p == nil {
				if tt.wantKid != "" {
					t.Errorf("PubKey.LoadKeyFromPem() kid = nil, want %v", tt.wantKid)
				} else {
					return
				}
			}
			if tt.p.Kid != tt.wantKid {
				t.Errorf("PubKey.LoadKeyFromPem() kid = %v, want %v", tt.p.Kid, tt.wantKid)
			}
		})
	}
}
