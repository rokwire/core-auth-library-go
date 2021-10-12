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

func TestAuthService_GetServiceReg(t *testing.T) {
	authPubKey := testutils.GetSamplePubKey()
	testServiceReg := authservice.ServiceReg{"test", "https://test.rokwire.com", nil}
	authServiceReg := authservice.ServiceReg{"auth", "https://auth.rokwire.com", authPubKey}

	serviceRegs := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	type args struct {
		serviceID string
	}
	tests := []struct {
		name    string
		args    args
		want    *authservice.ServiceReg
		wantErr bool
	}{
		{"return reg when found", args{"auth"}, &authServiceReg, false},
		{"return err when not found", args{"example"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := testutils.SetupTestAuthService(testutils.SetupMockServiceLoader(subscribed, serviceRegs, nil))
			if err != nil || a == nil {
				t.Errorf("Error initializing test auth service: %v", err)
				return
			}
			got, err := a.GetServiceReg(tt.args.serviceID)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthService.GetServiceReg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AuthService.GetServiceReg() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthService_GetServiceRegWithPubKey(t *testing.T) {
	authPubKey := testutils.GetSamplePubKey()
	testServiceReg := authservice.ServiceReg{"test", "https://test.rokwire.com", nil}
	authServiceReg := authservice.ServiceReg{"auth", "https://auth.rokwire.com", authPubKey}

	serviceRegs := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	type args struct {
		serviceID string
	}
	tests := []struct {
		name    string
		args    args
		want    *authservice.ServiceReg
		wantErr bool
	}{
		{"return reg when found and key valid", args{"auth"}, &authServiceReg, false},
		{"return err when found and key invalid", args{"test"}, nil, true},
		{"return err when not found", args{"example"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := testutils.SetupTestAuthService(testutils.SetupMockServiceLoader(subscribed, serviceRegs, nil))
			if err != nil || a == nil {
				t.Errorf("Error initializing test auth service: %v", err)
				return
			}
			got, err := a.GetServiceRegWithPubKey(tt.args.serviceID)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthService.GetServiceRegWithPubKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AuthService.GetServiceRegWithPubKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthService_SubscribeServices(t *testing.T) {
	testServiceReg := authservice.ServiceReg{ServiceID: "test", Host: "https://test.rokwire.com", PubKey: nil}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokwire.com", PubKey: nil}
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
			mockLoader := testutils.SetupMockServiceLoader(subscribed, serviceRegs, nil)
			a, err := testutils.SetupTestAuthService(mockLoader)
			if err != nil || a == nil {
				t.Errorf("Error initializing test auth service: %v", err)
				return
			}
			a.SubscribeServices(tt.args.serviceIDs, tt.args.reload)
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

func TestAuthService_ValidateServiceRegistration(t *testing.T) {
	testServiceReg := authservice.ServiceReg{ServiceID: "test", Host: "https://test.rokwire.com", PubKey: nil}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokwire.com", PubKey: nil}
	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}
	serviceRegsMissing := []authservice.ServiceReg{authServiceReg}
	subscribed := []string{"auth"}

	type args struct {
		serviceHost string
	}
	tests := []struct {
		name             string
		args             args
		loadServicesResp []authservice.ServiceReg
		wantErr          bool
	}{
		{"no error on registration found", args{"https://test.rokwire.com"}, serviceRegsValid, false},
		{"error on registration not found", args{"https://test.rokwire.com"}, serviceRegsMissing, true},
		{"error on wrong registration host", args{"https://test2.rokwire.com"}, serviceRegsValid, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceLoader(subscribed, tt.loadServicesResp, nil)
			a, err := testutils.SetupTestAuthService(mockLoader)
			if err != nil || a == nil {
				t.Errorf("Error initializing test auth service: %v", err)
				return
			}
			if err := a.ValidateServiceRegistration(tt.args.serviceHost); (err != nil) != tt.wantErr {
				t.Errorf("AuthService.ValidateServiceRegistration() error = %v, wantErr %v", err, tt.wantErr)
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

	testServiceReg := authservice.ServiceReg{"test", "https://test.rokwire.com", pubKey}
	testServiceRegNoKey := authservice.ServiceReg{"test", "https://test.rokwire.com", nil}
	testServiceRegWrongKey := authservice.ServiceReg{"test", "https://test.rokwire.com", wrongKey}

	authServiceReg := authservice.ServiceReg{"auth", "https://auth.rokwire.com", nil}

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
			mockLoader := testutils.SetupMockServiceLoader(subscribed, tt.loadServicesResp, nil)
			a, err := testutils.SetupTestAuthService(mockLoader)
			if err != nil || a == nil {
				t.Errorf("Error initializing test auth service: %v", err)
				return
			}
			if err := a.ValidateServiceRegistrationKey(tt.args.privKey); (err != nil) != tt.wantErr {
				t.Errorf("AuthService.ValidateServiceRegistrationKey() error = %v, wantErr %v", err, tt.wantErr)
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
