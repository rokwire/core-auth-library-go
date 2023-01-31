// Copyright 2023 Board of Trustees of the University of Illinois.
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

package keys_test

import (
	"testing"

	"github.com/rokwire/core-auth-library-go/v2/authutils"
	"github.com/rokwire/core-auth-library-go/v2/internal/testutils"
	"github.com/rokwire/core-auth-library-go/v2/keys"
)

func setupPubKeyFromPem(pem string) *keys.PubKey {
	return &keys.PubKey{KeyPem: pem, Alg: authutils.RS256}
}

func TestPrivKey_Encode(t *testing.T) {
	privKey, err := testutils.GetSamplePrivKey()
	if err != nil {
		t.Errorf("Error getting sample privkey: %v", err)
		return
	}

	type args struct {
		key *keys.PrivKey
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"success", args{privKey}, testutils.GetSamplePrivKeyPem() + "\n", false},
		{"return error on nil key", args{nil}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.args.key.Encode()
			if (err != nil) != tt.wantErr {
				t.Errorf("PrivKey.Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.args.key.KeyPem != tt.want {
				t.Errorf("PrivKey.Encode() = %v, want %v", tt.args.key.KeyPem, tt.want)
			}
		})
	}
}

// func TestPrivKey_Decode(t *testing.T) {
// 	privKey, err := testutils.GetSamplePrivKey()
// 	if err != nil {
// 		t.Errorf("Error getting sample privkey: %v", err)
// 		return
// 	}

// 	tests := []struct {
// 		name    string
// 		p       *keys.PrivKey
// 		wantErr bool
// 		wantKey *keys.PrivKey
// 	}{
// 		{"return nil and set Key property on valid pem", &keys.PrivKey{KeyPem: testutils.GetSamplePrivKeyPem()}, false, privKey},
// 		{"return error on invalid pem", &keys.PrivKey{KeyPem: "test"}, true, nil},
// 		{"return error on nil privkey", nil, true, nil},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if err := tt.p.Decode(); (err != nil) != tt.wantErr {
// 				t.Errorf("PrivKey.Decode() error = %v, wantErr %v", err, tt.wantErr)
// 			}
// 			if tt.wantKey == nil {
// 				if tt.p != nil && tt.p.Key != nil {
// 					t.Errorf("PrivKey.Decode() key = %v, want nil", tt.p.Key)
// 				}
// 			} else {
// 				if !tt.p.Equal(tt.wantKey) {
// 					t.Errorf("PrivKey.Decode() key = %v, want %v", tt.p.Key, tt.wantKey)
// 				}
// 			}
// 		})
// 	}
// }

func TestPrivKey_Decrypt(t *testing.T) {
	tests := []struct {
		name    string
		p       *keys.PrivKey
		wantErr bool
		wantKey *keys.PrivKey
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

		})
	}
}

func TestPrivKey_Sign(t *testing.T) {
	tests := []struct {
		name    string
		p       *keys.PrivKey
		wantErr bool
		wantKey *keys.PrivKey
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

		})
	}
}

func TestPrivKey_PubKey(t *testing.T) {
	tests := []struct {
		name    string
		p       *keys.PrivKey
		wantErr bool
		wantKey *keys.PrivKey
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

		})
	}
}

func TestPrivKey_Equal(t *testing.T) {
	tests := []struct {
		name    string
		p       *keys.PrivKey
		wantErr bool
		wantKey *keys.PrivKey
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

		})
	}
}

func TestPubKey_Encode(t *testing.T) {
	pubKey, err := testutils.GetSamplePubKey()
	if err != nil {
		t.Errorf("Error getting sample pubkey: %v", err)
		return
	}

	type args struct {
		key *keys.PubKey
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"success", args{pubKey}, testutils.GetSamplePubKeyPem() + "\n", false},
		{"return error on nil key", args{nil}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.args.key.Encode()
			if (err != nil) != tt.wantErr {
				t.Errorf("PubKey.Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.args.key.KeyPem != tt.want {
				t.Errorf("PubKey.Encode() = %v, want %v", tt.args.key.KeyPem, tt.want)
			}
		})
	}
}

// func TestPubKey_Decode(t *testing.T) {
// 	pubKey, err := testutils.GetSamplePubKey()
// 	if err != nil {
// 		t.Errorf("Error getting sample pubkey: %v", err)
// 		return
// 	}

// 	tests := []struct {
// 		name      string
// 		p         *keys.PubKey
// 		wantErr   bool
// 		wantKey   *keys.PubKey
// 		wantKeyID string
// 	}{
// 		{"return nil and set Key, Kid property on valid pem", setupPubKeyFromPem(testutils.GetSamplePubKeyPem()), false, pubKey, testutils.GetSamplePubKeyFingerprint()},
// 		{"return error on invalid pem", setupPubKeyFromPem("test"), true, nil, ""},
// 		{"return error on nil pubkey", nil, true, nil, ""},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if err := tt.p.Decode(); (err != nil) != tt.wantErr {
// 				t.Errorf("PubKey.Decode() error = %v, wantErr %v", err, tt.wantErr)
// 			}
// 			if tt.wantKey == nil {
// 				if tt.p != nil && tt.p.Key != nil {
// 					t.Errorf("PubKey.Decode() key = %v, want nil", tt.p.Key)
// 				}
// 			} else {
// 				if !tt.p.Equal(tt.wantKey) {
// 					t.Errorf("PubKey.Decode() key = %v, want %v", tt.p.Key, tt.wantKey)
// 				}
// 			}
// 			if tt.p == nil {
// 				if tt.wantKeyID != "" {
// 					t.Errorf("PubKey.Decode() kid = nil, want %v", tt.wantKeyID)
// 				} else {
// 					return
// 				}
// 			}
// 			if tt.p.KeyID != tt.wantKeyID {
// 				t.Errorf("PubKey.Decode() kid = %v, want %v", tt.p.KeyID, tt.wantKeyID)
// 			}
// 		})
// 	}
// }

func TestPubKey_Encrypt(t *testing.T) {
	tests := []struct {
		name    string
		p       *keys.PrivKey
		wantErr bool
		wantKey *keys.PrivKey
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

		})
	}
}

func TestPubKey_Verify(t *testing.T) {
	tests := []struct {
		name    string
		p       *keys.PrivKey
		wantErr bool
		wantKey *keys.PrivKey
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

		})
	}
}

func TestPubKey_SetKeyFingerprint(t *testing.T) {
	key, err := testutils.GetSamplePubKey()
	if err != nil {
		t.Errorf("Error getting sample pubkey: %v", err)
		return
	}

	type args struct {
		key *keys.PubKey
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"returns fingerprint for valid key", args{key}, testutils.GetSamplePubKeyFingerprint(), false},
		{"errors on nil key", args{nil}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.args.key.SetKeyFingerprint()
			if (err != nil) != tt.wantErr {
				t.Errorf("PubKey.SetKeyFingerprint() = %v, error = %v, wantErr %v", tt.args.key.KeyID, err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.args.key.KeyID != tt.want {
				t.Errorf("PubKey.SetKeyFingerprint() = %v, want %v", tt.args.key.KeyID, tt.want)
			}
		})
	}
}

func TestPubKey_Equal(t *testing.T) {
	tests := []struct {
		name    string
		p       *keys.PrivKey
		wantErr bool
		wantKey *keys.PrivKey
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

		})
	}
}

func TestNewAsymmetricKeyPair(t *testing.T) {
	type args struct {
		keyType string
		bits    int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"generate rsa pair", args{keyType: authutils.RS256, bits: 2048}, false},
		{"generate ec256 pair", args{keyType: authutils.EC256}, false},
		{"generate ec384 pair", args{keyType: authutils.EC384}, false},
		{"generate ec512 pair", args{keyType: authutils.EC512}, false},
		{"generate edwards curve pair", args{keyType: authutils.EdDSA}, false},
		{"error on unrecognized key type", args{keyType: "test"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := keys.NewAsymmetricKeyPair(tt.args.keyType, tt.args.bits)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAsymmetricKeyPair() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
