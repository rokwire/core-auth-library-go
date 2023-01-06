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

package testutils

import (
	"github.com/rokwire/core-auth-library-go/v2/authservice"
	"github.com/rokwire/core-auth-library-go/v2/authservice/mocks"
)

// GetSamplePubKeyPem returns a sample public key PEM
//
//	Matches GetSamplePrivKeyPem
func GetSamplePubKeyPem() string {
	return `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq2gWKpPRb2xQRee4OXbg
KMzGAy8aPcAqgfL8xmi7tozoi917QHL4qi4PHn/7v0K6eAKdq1Vh6dlLmcWbl1Gy
4IDkf8bDAmUKdezWw6jrnKTW+XZ8S5lsqNSYH07R7aRxJPlugta13fMWphs58LTo
whQcu1zBCqjEAUooqyWq3XDmic4wbVIp5HvlaayZ7Q+ifDliULxSRqAAUrQZ5DQv
gtnZ3Dq/93gGbAjnpXl3txfgeQH5NpJN6fFsjm48PFP+Byw5VOslOBh6dtaI6ldR
Am8DIClWwZ9867p8gpeZpvBsE/sIXUEs/r608oZf6+D3OfIfQUkCq9Knxjgdho8E
SwIDAQAB
-----END RSA PUBLIC KEY-----`
}

// GetSamplePubKey returns a sample public key
func GetSamplePubKey() *authservice.PubKey {
	key := authservice.PubKey{
		KeyPem: GetSamplePubKeyPem(),
		Alg:    "RS256",
	}

	key.LoadKeyFromPem()

	return &key
}

// GetSamplePubKeyFingerprint returns a sample public key fingerprint
func GetSamplePubKeyFingerprint() string {
	return "SHA256:8Kxg2cK9x03ofiEevL0hwAoW330xdy4vjD713fLLkzs="
}

// GetSamplePrivKeyPem returns a sample private key PEM
//
//	Matches GetSamplePubKeyPem
func GetSamplePrivKeyPem() string {
	return `-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCraBYqk9FvbFBF
57g5duAozMYDLxo9wCqB8vzGaLu2jOiL3XtAcviqLg8ef/u/Qrp4Ap2rVWHp2UuZ
xZuXUbLggOR/xsMCZQp17NbDqOucpNb5dnxLmWyo1JgfTtHtpHEk+W6C1rXd8xam
GznwtOjCFBy7XMEKqMQBSiirJardcOaJzjBtUinke+VprJntD6J8OWJQvFJGoABS
tBnkNC+C2dncOr/3eAZsCOeleXe3F+B5Afk2kk3p8WyObjw8U/4HLDlU6yU4GHp2
1ojqV1ECbwMgKVbBn3zrunyCl5mm8GwT+whdQSz+vrTyhl/r4Pc58h9BSQKr0qfG
OB2GjwRLAgMBAAECggEACmXg+u6rYC/LaENaPNdRfo76r9bnJ9Vk+ivULHHywuxK
pkMmhtwk6gMZIrMquIAsI4SaP9Xkf8LIKTbSrWmk21xdLeiZMJU2tb0UQ5uXM22H
FLV4I9Ge6X0AEbj+srt+9MN239QIKjF3Jlbi6P0ogUGBzGjEsNrGMboevCu6A2yw
wToue4DUNBBE4hpXyozrTKBEFJE0YNIEcV+hSuMbqEdcQUKVXIu5gbPg5LocrAo+
K0XA9hPIvhrExd9jYGuZU5ilGaG74uA4s9Y1kWPoT198Wn4bPj29wz5x5PuKzXXV
B3vR4oEs6DMhyjjpUUSQ+lEzR5xTLFZQ3hsAYOO9LQKBgQC24fK20QHKoYjmablS
qryv8TSS1rD+KNM0DrmIoIBXFnLWc6R2K3GuLAfW1+uKBJ1xLL4WxjKpiOMK4q+A
oldmLEoiheM3vmwDEmzwVXzIzRWs667Jge6lOx2yWAtFPZ4Zb4Gt5Vn1CyBmvdEu
Y5VSCek8/6XlyYmhpmzFP3lFhQKBgQDv75EOdHCWSXIEfZZ1mJdeflV9Wvhzj6bm
Zub2kODVj4lN9lVsfcvwDfJa5J/0oe4s4GBnhU26zc8iJMFJsL8LyPcxRRTiEiD8
8A1sw/LnxpuSirKeFCh7mddRXLH+mqtgtdB+WvNSHd3E6Ic12oEMG4YHOZvn140F
yMgLIRAjjwKBgG8JquNC7XKJN2SmhmXh0mSE7+XDwnzebrWpxw5kXOgDckAwwIcb
A4+7nhrcyF7pRGqFvvh26CW1PhzK28IfTy9y7qQdZILg9BW9ZzVYwkXs9x8hjeM9
J5dc2EADYvxsWASbhkH+AetdERQwZcRjpDLGX72wfpqRDiZ+tIXibxA9AoGAXDRD
GTvz/D0TPNiKVnyiRuTjs32fFsGwkMAgp8Y7MLatPDGa2EtrcL/bT8SmF5uW7NX5
Fi8rFMt8exGG2eu7Lys2m0+B2/K9jJYvgom2sg0nwePdClSSzhTros+tczs6+rpD
+hq3gOoLTF1TgIWMq/tzwRkJacny3rMu9N/q1M8CgYEAnP088B4Ks+Vt09PZWLEt
EFnnfkZZQOwDvZchZgMbwmCpX7yZt843kAZdGRLSQIkyjJflI/5h6Efa1Veu2G2x
SafvGimk6hxxEG8TAP1/mEYoJstrXi9leFpG/wxiD7xGIY2w9KYLqpO73KS5Gfdr
YMXr++Wtm5aWdGeQjoQX3VA=
-----END RSA PRIVATE KEY-----`
}

// GetSamplePrivKey returns a sample private key
func GetSamplePrivKey() *authservice.PrivKey {
	privKey := authservice.PrivKey{KeyPem: GetSamplePrivKeyPem()}

	privKey.LoadKeyFromPem()

	return &privKey
}

// SetupTestAuthService returns a test AuthService
func SetupTestAuthService(serviceID string, serviceHost string) *authservice.AuthService {
	return &authservice.AuthService{ServiceID: serviceID, ServiceHost: serviceHost}
}

// SetupMockServiceRegLoader returns a mock ServiceRegLoader
func SetupMockServiceRegLoader(authService *authservice.AuthService, subscribed []string, result []authservice.ServiceReg, err error) *mocks.ServiceRegLoader {
	mockLoader := mocks.NewServiceRegLoader(authService, subscribed)
	mockLoader.On("LoadServices").Return(result, err)
	return mockLoader
}

// SetupTestServiceRegManager returns a test ServiceRegManager
func SetupTestServiceRegManager(authService *authservice.AuthService, mockDataLoader *mocks.ServiceRegLoader) (*authservice.ServiceRegManager, error) {
	return authservice.NewTestServiceRegManager(authService, mockDataLoader)
}

// SetupMockServiceAccountTokenLoader returns a mock ServiceAccountLoader which loads a single access token
func SetupMockServiceAccountTokenLoader(authService *authservice.AuthService, appID string, orgID string, token *authservice.AccessToken, err error) *mocks.ServiceAccountLoader {
	mockLoader := mocks.NewServiceAccountLoader(authService)
	mockLoader.On("LoadAccessToken", appID, orgID).Return(token, err)
	return mockLoader
}

// SetupMockServiceAccountTokensLoader returns a mock ServiceAccountLoader which loads a set of access tokens
func SetupMockServiceAccountTokensLoader(authService *authservice.AuthService, tokens map[authservice.AppOrgPair]authservice.AccessToken, err error) *mocks.ServiceAccountLoader {
	mockLoader := mocks.NewServiceAccountLoader(authService)
	mockLoader.On("LoadAccessTokens").Return(tokens, err)
	return mockLoader
}

// SetupTestServiceAccountManager returns a test ServiceAccountManager
func SetupTestServiceAccountManager(authService *authservice.AuthService, mockDataLoader *mocks.ServiceAccountLoader, loadTokens bool) (*authservice.ServiceAccountManager, error) {
	return authservice.NewTestServiceAccountManager(authService, mockDataLoader, loadTokens)
}

// SetupExampleMockServiceRegLoader returns an example mock ServiceRegLoader
func SetupExampleMockServiceRegLoader() *mocks.ServiceRegLoader {
	testServiceReg := authservice.ServiceReg{ServiceID: "sample", Host: "https://sample.rokwire.com", PubKey: nil}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokwire.com", PubKey: GetSamplePubKey()}
	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}

	mockLoader := mocks.NewServiceRegLoader(SetupTestAuthService("sample", "https://sample.rokwire.com"), nil)
	mockLoader.On("LoadServices").Return(serviceRegsValid, nil)

	return mockLoader
}
