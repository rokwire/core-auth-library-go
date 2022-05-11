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
	"crypto/rsa"

	"github.com/golang-jwt/jwt"
	"github.com/rokwire/core-auth-library-go/authservice"
	"github.com/rokwire/core-auth-library-go/authservice/mocks"
)

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

func GetSamplePubKey() *authservice.PubKey {
	key := authservice.PubKey{
		KeyPem: GetSamplePubKeyPem(),
		Alg:    "RS256",
	}

	key.LoadKeyFromPem()

	return &key
}

func GetSamplePubKeyFingerprint() string {
	return "SHA256:I3HxcO3FpUM6MG7+rCASuePfl92JEcdz2htV7SP0Y20="
}

func GetSamplePrivKeyPem() string {
	// Matches GetSamplePubKeyPem
	return `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAq2gWKpPRb2xQRee4OXbgKMzGAy8aPcAqgfL8xmi7tozoi917
QHL4qi4PHn/7v0K6eAKdq1Vh6dlLmcWbl1Gy4IDkf8bDAmUKdezWw6jrnKTW+XZ8
S5lsqNSYH07R7aRxJPlugta13fMWphs58LTowhQcu1zBCqjEAUooqyWq3XDmic4w
bVIp5HvlaayZ7Q+ifDliULxSRqAAUrQZ5DQvgtnZ3Dq/93gGbAjnpXl3txfgeQH5
NpJN6fFsjm48PFP+Byw5VOslOBh6dtaI6ldRAm8DIClWwZ9867p8gpeZpvBsE/sI
XUEs/r608oZf6+D3OfIfQUkCq9Knxjgdho8ESwIDAQABAoIBAApl4Pruq2Avy2hD
WjzXUX6O+q/W5yfVZPor1Cxx8sLsSqZDJobcJOoDGSKzKriALCOEmj/V5H/CyCk2
0q1ppNtcXS3omTCVNrW9FEOblzNthxS1eCPRnul9ABG4/rK7fvTDdt/UCCoxdyZW
4uj9KIFBgcxoxLDaxjG6HrwrugNssME6LnuA1DQQROIaV8qM60ygRBSRNGDSBHFf
oUrjG6hHXEFClVyLuYGz4OS6HKwKPitFwPYTyL4axMXfY2BrmVOYpRmhu+LgOLPW
NZFj6E9ffFp+Gz49vcM+ceT7is111Qd70eKBLOgzIco46VFEkPpRM0ecUyxWUN4b
AGDjvS0CgYEAtuHyttEByqGI5mm5Uqq8r/E0ktaw/ijTNA65iKCAVxZy1nOkditx
riwH1tfrigSdcSy+FsYyqYjjCuKvgKJXZixKIoXjN75sAxJs8FV8yM0VrOuuyYHu
pTsdslgLRT2eGW+BreVZ9QsgZr3RLmOVUgnpPP+l5cmJoaZsxT95RYUCgYEA7++R
DnRwlklyBH2WdZiXXn5VfVr4c4+m5mbm9pDg1Y+JTfZVbH3L8A3yWuSf9KHuLOBg
Z4VNus3PIiTBSbC/C8j3MUUU4hIg/PANbMPy58abkoqynhQoe5nXUVyx/pqrYLXQ
flrzUh3dxOiHNdqBDBuGBzmb59eNBcjICyEQI48CgYBvCarjQu1yiTdkpoZl4dJk
hO/lw8J83m61qccOZFzoA3JAMMCHGwOPu54a3Mhe6URqhb74dugltT4cytvCH08v
cu6kHWSC4PQVvWc1WMJF7PcfIY3jPSeXXNhAA2L8bFgEm4ZB/gHrXREUMGXEY6Qy
xl+9sH6akQ4mfrSF4m8QPQKBgFw0Qxk78/w9EzzYilZ8okbk47N9nxbBsJDAIKfG
OzC2rTwxmthLa3C/20/EphebluzV+RYvKxTLfHsRhtnruy8rNptPgdvyvYyWL4KJ
trINJ8Hj3QpUks4U66LPrXM7Ovq6Q/oat4DqC0xdU4CFjKv7c8EZCWnJ8t6zLvTf
6tTPAoGBAJz9PPAeCrPlbdPT2VixLRBZ535GWUDsA72XIWYDG8JgqV+8mbfON5AG
XRkS0kCJMoyX5SP+YehH2tVXrthtsUmn7xoppOoccRBvEwD9f5hGKCbLa14vZXha
Rv8MYg+8RiGNsPSmC6qTu9ykuRn3a2DF6/vlrZuWlnRnkI6EF91Q
-----END RSA PRIVATE KEY-----`
}

func GetSamplePrivKey() *rsa.PrivateKey {
	privKey, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(GetSamplePrivKeyPem()))
	return privKey
}

func SetupMockServiceRegLoader(subscribed []string, result []authservice.ServiceReg, err error) *mocks.ServiceRegLoader {
	mockLoader := mocks.NewServiceRegLoader(subscribed)
	mockLoader.On("LoadServices").Return(result, err)
	return mockLoader
}

func SetupTestServiceRegManager(mockDataLoader *mocks.ServiceRegLoader) (*authservice.ServiceRegManager, error) {
	return authservice.NewTestServiceRegManager("test", "https://test.rokwire.com", mockDataLoader)
}

func SetupExampleMockLoader() *mocks.ServiceRegLoader {
	testServiceReg := authservice.ServiceReg{ServiceID: "sample", Host: "https://sample.rokwire.com", PubKey: nil}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokwire.com", PubKey: GetSamplePubKey()}
	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}

	mockLoader := mocks.NewServiceRegLoader(nil)
	mockLoader.On("LoadServices").Return(serviceRegsValid, nil)

	return mockLoader
}
