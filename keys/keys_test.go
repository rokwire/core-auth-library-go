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
	"encoding/base64"
	"testing"

	"github.com/rokwire/core-auth-library-go/v2/internal/testutils"
	"github.com/rokwire/core-auth-library-go/v2/keys"
)

func setupPubKeyFromPem(pem string) *keys.PubKey {
	return &keys.PubKey{KeyPem: pem, Alg: keys.RS256}
}

func TestPrivKey_Encode(t *testing.T) {
	rsaKey, err := testutils.GetSamplePrivKey(keys.RS256)
	if err != nil {
		t.Errorf("Error getting sample rsa privkey: %v", err)
		return
	}
	ecKey, err := testutils.GetSamplePrivKey(keys.ES256)
	if err != nil {
		t.Errorf("Error getting sample ec privkey: %v", err)
		return
	}
	edKey, err := testutils.GetSamplePrivKey(keys.EdDSA)
	if err != nil {
		t.Errorf("Error getting sample eddsa privkey: %v", err)
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
		{"success rsa", args{rsaKey}, testutils.GetSampleRSAPrivKeyPem() + "\n", false},
		{"success ec", args{ecKey}, testutils.GetSampleES256PrivKeyPem() + "\n", false},
		{"success eddsa", args{edKey}, testutils.GetSampleEdPrivKeyPem() + "\n", false},
		{"success eddsa", args{&keys.PrivKey{Key: ecKey.Key, Alg: "test"}}, "", true},
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

func TestPrivKey_Decode(t *testing.T) {
	privKey, err := testutils.GetSamplePrivKey(keys.RS384)
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
		wantErr bool
		wantKey *keys.PrivKey
	}{
		{"return nil and set Key property on valid pem", args{&keys.PrivKey{KeyPem: testutils.GetSampleRSAPrivKeyPem(), Alg: keys.RS384}}, false, privKey},
		{"return error on invalid pem", args{&keys.PrivKey{KeyPem: "test", Alg: keys.RS384}}, true, nil},
		{"return error on invalid alg", args{&keys.PrivKey{KeyPem: "test", Alg: "test"}}, true, nil},
		{"return error on nil privkey", args{nil}, true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.args.key.Decode(); (err != nil) != tt.wantErr {
				t.Errorf("PrivKey.Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !tt.args.key.Equal(tt.wantKey) {
				t.Errorf("PrivKey.Decode() key = %v, want %v", tt.args.key.Key, tt.wantKey)
			}
		})
	}
}

func TestPrivKey_Decrypt(t *testing.T) {
	rsaKey, err := testutils.GetSamplePrivKey(keys.RS512)
	if err != nil {
		t.Errorf("Error getting sample rsa privkey: %v", err)
		return
	}
	ecKey, err := testutils.GetSamplePrivKey(keys.ES256)
	if err != nil {
		t.Errorf("Error getting sample ec privkey: %v", err)
		return
	}
	badRSAKey := &keys.PrivKey{Alg: keys.RS512, Key: ecKey.Key}

	labeledCipherText := "ASiO2g5jWb5AuHPKGk5nVy8wRPFL3g6pm8BywGAJg3Gd880OWXBCbsnober4Lg4+RKOPyPo/JUZiFrN2cgbNc+TEJwyFWBhi/vaYPStIY4ulZM8QS7TrkG9bkcjIeUH3oVI4gbjD7nUgAl3guY0X3FfZfe5JngPkHrzYM5cvlM1vIHLJ0cc83FBDzpwD+7U8AWFhu9GeYgQhPdgPSV77wDR6gTgjgN03SxzUAM4V4h4wrfcCM9hHsdnmkfqh/A2ZEi/bsSNXzt6Fe+Du+yAUxxxulFBCksabJoWfxcMdGH8pJhU4uf32wHeTg5DNhJ2K/JKz0Rl83rOs7T6C8/uE6w=="
	unlabeledCipherText := "WtFV0Q4j7Z5gx4M6TygT2jkZw3mKXyL7W72TZIQH9ftDP/3ZlU2RYXm2G0Z8deMeRgAs8bQGlb18c1wKI/jchoiGEib1Fi8091ehsbyJkAEhdUH1NVHkhnBMS/GwFId5MaiHgs9XX6erWghfsQbf+6wIkpvme72GpCqeuEVSh8SAY2HK6uNUTV9h/oNOU9uz6fxTMs3yPO6jHgGhxzmEl+RDPjp9Bl3JgBMyJYBlNH5a99ZkfGCVGlayLEO6pmMLKEwHj96o87XhYT6kGrdgETBNmNLlve69NBH+fgskUH+1vkr2AXfT13dAnjXHQofFXF/B0YBmXtbbyXY9tfKACQ=="
	type args struct {
		key        *keys.PrivKey
		cipherText string
		label      []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"success", args{rsaKey, labeledCipherText, []byte("This is a test label.")}, "This is a test message.", false},
		{"success missing label", args{rsaKey, unlabeledCipherText, nil}, "This is a test message.", false},
		{"unsupported key type", args{ecKey, labeledCipherText, []byte("This is a test label.")}, "", true},
		{"incorrect label", args{rsaKey, labeledCipherText, []byte("incorrect label")}, "", true},
		{"mismatched key and alg", args{badRSAKey, labeledCipherText, []byte("This is a test label.")}, "", true},
		{"errors on nil key", args{nil, labeledCipherText, []byte("This is a test label.")}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decodedCT, err := base64.StdEncoding.DecodeString(tt.args.cipherText)
			if err != nil {
				t.Errorf("PubKey.Decrypt() error decoding ciphertext: %v", err)
				return
			}
			got, err := tt.args.key.Decrypt(decodedCT, tt.args.label)
			if (err != nil) != tt.wantErr {
				t.Errorf("PubKey.Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("PubKey.Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrivKey_Sign(t *testing.T) {
	rsaKey, err := testutils.GetSamplePrivKey(keys.RS256)
	if err != nil {
		t.Errorf("Error getting sample rsa privkey: %v", err)
		return
	}
	ecKey, err := testutils.GetSamplePrivKey(keys.ES256)
	if err != nil {
		t.Errorf("Error getting sample ec privkey: %v", err)
		return
	}
	edKey, err := testutils.GetSamplePrivKey(keys.EdDSA)
	if err != nil {
		t.Errorf("Error getting sample eddsa privkey: %v", err)
		return
	}

	badKey := &keys.PrivKey{Alg: "test"}

	type args struct {
		key     *keys.PrivKey
		message []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"success rsa key", args{rsaKey, []byte("This is a test.")}, false},
		{"success empty message", args{rsaKey, nil}, false},
		{"success ec key", args{ecKey, []byte("This is a test.")}, false},
		{"success eddsa key", args{edKey, []byte("This is a test.")}, false},
		{"return error on unsupported alg", args{badKey, []byte("This is a test.")}, true},
		{"return error on nil key", args{nil, []byte("This is a test.")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.args.key.Sign(tt.args.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("PrivKey.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) == 0 {
				t.Errorf("PrivKey.Sign() empty")
			}
		})
	}
}

func TestPrivKey_PubKey(t *testing.T) {
	rsaKey, err := testutils.GetSamplePrivKey(keys.RS256)
	if err != nil {
		t.Errorf("Error getting sample rsa privkey: %v", err)
		return
	}
	ecKey, err := testutils.GetSamplePrivKey(keys.ES256)
	if err != nil {
		t.Errorf("Error getting sample ec privkey: %v", err)
		return
	}
	edKey, err := testutils.GetSamplePrivKey(keys.EdDSA)
	if err != nil {
		t.Errorf("Error getting sample eddsa privkey: %v", err)
		return
	}

	badRSAKey := &keys.PrivKey{Key: edKey.Key, Alg: keys.RS256}
	unsupportedAlgKey := &keys.PrivKey{Key: edKey.Key, Alg: "test"}

	rsaPubKey, err := testutils.GetSamplePubKey(keys.RS256)
	if err != nil {
		t.Errorf("Error getting sample rsa pubkey: %v", err)
		return
	}
	ecPubKey, err := testutils.GetSamplePubKey(keys.ES256)
	if err != nil {
		t.Errorf("Error getting sample ec pubkey: %v", err)
		return
	}
	edPubKey, err := testutils.GetSamplePubKey(keys.EdDSA)
	if err != nil {
		t.Errorf("Error getting sample eddsa pubkey: %v", err)
		return
	}

	type args struct {
		key *keys.PrivKey
	}
	tests := []struct {
		name    string
		args    args
		wantKey *keys.PubKey
		wantErr bool
	}{
		{"success rsa key", args{rsaKey}, rsaPubKey, false},
		{"success ec key", args{ecKey}, ecPubKey, false},
		{"success eddsa key", args{edKey}, edPubKey, false},
		{"error unsupported alg", args{unsupportedAlgKey}, nil, true},
		{"error mismatched key alg", args{badRSAKey}, nil, true},
		{"error on nil key", args{nil}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.args.key.PubKey()
			if (err != nil) != tt.wantErr {
				t.Errorf("PrivKey.PubKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !got.Equal(tt.wantKey) {
				t.Errorf("PrivKey.PubKey() = %v, want %v", got, tt.wantKey)
			}
		})
	}
}

func TestPrivKey_Equal(t *testing.T) {
	rsaKey, err := testutils.GetSamplePrivKey(keys.RS256)
	if err != nil {
		t.Errorf("Error getting sample rsa privkey: %v", err)
		return
	}
	rsaKey2, err := testutils.GetSamplePrivKey(keys.RS256)
	if err != nil {
		t.Errorf("Error getting sample rsa privkey: %v", err)
		return
	}
	rsaKey3, err := testutils.GetSamplePrivKey(keys.RS384)
	if err != nil {
		t.Errorf("Error getting sample rsa privkey: %v", err)
		return
	}
	edKey, err := testutils.GetSamplePrivKey(keys.EdDSA)
	if err != nil {
		t.Errorf("Error getting sample eddsa privkey: %v", err)
		return
	}
	badKey := &keys.PrivKey{Key: edKey, Alg: "test"}

	type args struct {
		key   *keys.PrivKey
		other *keys.PrivKey
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"success rsa keys", args{rsaKey, rsaKey2}, true},
		{"error rsa key alg", args{rsaKey, rsaKey3}, false},
		{"error key types", args{rsaKey2, edKey}, false},
		{"error nil key", args{nil, edKey}, false},
		{"error nil other key", args{rsaKey, nil}, false},
		{"error unknown key type", args{badKey, badKey}, false},
		{"success nil keys", args{nil, nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.args.key.Equal(tt.args.other)
			if got != tt.want {
				t.Errorf("PrivKey.Equal() = %v, wantErr %v", got, tt.want)
			}
		})
	}
}

func TestPubKey_Encode(t *testing.T) {
	rsaKey, err := testutils.GetSamplePubKey(keys.RS256)
	if err != nil {
		t.Errorf("Error getting sample rsa pubkey: %v", err)
		return
	}
	ecKey, err := testutils.GetSamplePubKey(keys.ES256)
	if err != nil {
		t.Errorf("Error getting sample ec pubkey: %v", err)
		return
	}
	edKey, err := testutils.GetSamplePubKey(keys.EdDSA)
	if err != nil {
		t.Errorf("Error getting sample eddsa pubkey: %v", err)
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
		{"success rsa", args{rsaKey}, testutils.GetSampleRSAPubKeyPem() + "\n", false},
		{"success ec", args{ecKey}, testutils.GetSampleES256PubKeyPem() + "\n", false},
		{"success eddsa", args{edKey}, testutils.GetSampleEdPubKeyPem() + "\n", false},
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

func TestPubKey_Decode(t *testing.T) {
	pubKey, err := testutils.GetSamplePubKey(keys.RS384)
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
		wantErr bool
		wantKey *keys.PubKey
	}{
		{"return nil and set Key property on valid pem", args{&keys.PubKey{KeyPem: testutils.GetSampleRSAPubKeyPem(), Alg: keys.RS384}}, false, pubKey},
		{"return error on invalid pem", args{&keys.PubKey{KeyPem: "test", Alg: keys.RS384}}, true, nil},
		{"return error on invalid alg", args{&keys.PubKey{KeyPem: "test", Alg: "test"}}, true, nil},
		{"return error on nil privkey", args{nil}, true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.args.key.Decode(); (err != nil) != tt.wantErr {
				t.Errorf("PubKey.Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !tt.args.key.Equal(tt.wantKey) {
				t.Errorf("PubKey.Decode() key = %v, want %v", tt.args.key.Key, tt.wantKey)
			}
		})
	}
}

func TestPubKey_Encrypt(t *testing.T) {
	rsaKey, err := testutils.GetSamplePubKey(keys.RS512)
	if err != nil {
		t.Errorf("Error getting sample rsa pubkey: %v", err)
		return
	}
	ecKey, err := testutils.GetSamplePubKey(keys.ES256)
	if err != nil {
		t.Errorf("Error getting sample ec pubkey: %v", err)
		return
	}
	badRSAKey := &keys.PubKey{Alg: keys.RS512, Key: ecKey.Key}

	type args struct {
		key     *keys.PubKey
		message []byte
		label   []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"success", args{rsaKey, []byte("This is a test message."), []byte("This is a test label.")}, false},
		{"success missing label", args{rsaKey, []byte("This is a test message."), nil}, false},
		{"unsupported key type", args{ecKey, []byte("This is a test message."), []byte("This is a test label.")}, true},
		{"mismatched key and alg", args{badRSAKey, []byte("This is a test message."), []byte("This is a test label.")}, true},
		{"errors on nil key", args{nil, []byte("This is a test message."), []byte("This is a test label.")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.args.key.Encrypt(tt.args.message, tt.args.label)
			if (err != nil) != tt.wantErr {
				t.Errorf("PubKey.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) == 0 {
				t.Errorf("PubKey.Encrypt() empty")
			}
		})
	}
}

func TestPubKey_Verify(t *testing.T) {
	rsaKey, err := testutils.GetSamplePubKey(keys.RS256)
	if err != nil {
		t.Errorf("Error getting sample rsa pubkey: %v", err)
		return
	}
	ecKey, err := testutils.GetSamplePubKey(keys.ES256)
	if err != nil {
		t.Errorf("Error getting sample ec pubkey: %v", err)
		return
	}
	edKey, err := testutils.GetSamplePubKey(keys.EdDSA)
	if err != nil {
		t.Errorf("Error getting sample eddsa pubkey: %v", err)
		return
	}

	type args struct {
		key       *keys.PubKey
		message   []byte
		signature string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"success rsa", args{rsaKey, []byte("This is a test."), "aDyy8hzndck19hBzUoFQWDRy1IF1pvDXzra1daTpq_zfCmMXhp1XGh-13UGertuBpBr21bbGh8p9miQnLrJbutqT2-zf1pcBHPIkqHK8s-I29RQQNVa2vXvnjHO3omW9ntmhnqa5puJolCqmMmimQV0zJ0Ljy79goGaKaLPSEd3hxSH3Ayhauhizh2f5s13PmXxHJYAXduperGOMAXZ_xFIGx732wOE05xXASKbcT63hqq6TWnVGXngC0i4JaFX4Kq4JeUXCB5bjh0dGfTf6ODcHENkIiNQCtNhoiibMakasW0jZHm1h0ceYuyJO-WsgSi2s9M9b4mHnAD1IX--jlQ"}, false},
		{"success ec", args{ecKey, []byte("This is a test."), "m7nGICA4C5_i14SvpSrMPQTfBwkdOdfpLRumEKkwi0byh-Hs-vp1VyzYJqOecQgnVFqZmoOZmg4Qi59qqadTNQ"}, false},
		{"success eddsa", args{edKey, []byte("This is a test."), "eVXXxIKSBYSm-OgblFslA4VGAML3hOfZpH1oYPg9K4bSiDCU2GxSNwq9SEkPwZMFE-dAHla3O7sVGqioXzx3Ag"}, false},
		{"errors on nil key", args{nil, []byte("This is a test."), ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.args.key.Verify(tt.args.message, tt.args.signature)
			if (err != nil) != tt.wantErr {
				t.Errorf("PubKey.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPubKey_SetKeyFingerprint(t *testing.T) {
	rsaKey, err := testutils.GetSamplePubKey(keys.RS256)
	if err != nil {
		t.Errorf("Error getting sample rsa pubkey: %v", err)
		return
	}
	ecKey, err := testutils.GetSamplePubKey(keys.ES256)
	if err != nil {
		t.Errorf("Error getting sample ec pubkey: %v", err)
		return
	}
	edKey, err := testutils.GetSamplePubKey(keys.EdDSA)
	if err != nil {
		t.Errorf("Error getting sample eddsa pubkey: %v", err)
		return
	}

	badRSAKey := &keys.PubKey{Key: edKey.Key, Alg: keys.RS256}
	unsupportedAlgKey := &keys.PubKey{Key: edKey.Key, Alg: "test"}

	type args struct {
		key *keys.PubKey
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"returns fingerprint for valid rsa key", args{rsaKey}, testutils.GetSamplePubKeyFingerprint("RSA"), false},
		{"returns fingerprint for valid ec key", args{ecKey}, testutils.GetSamplePubKeyFingerprint("EC"), false},
		{"returns fingerprint for valid eddsa key", args{edKey}, testutils.GetSamplePubKeyFingerprint("EdDSA"), false},
		{"error on mismatched key with rsa", args{badRSAKey}, "", true},
		{"error on unsupported alg", args{unsupportedAlgKey}, "", true},
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
	rsaKey, err := testutils.GetSamplePubKey(keys.RS256)
	if err != nil {
		t.Errorf("Error getting sample rsa pubkey: %v", err)
		return
	}
	rsaKey2, err := testutils.GetSamplePubKey(keys.RS256)
	if err != nil {
		t.Errorf("Error getting sample rsa pubkey: %v", err)
		return
	}
	rsaKey3, err := testutils.GetSamplePubKey(keys.RS384)
	if err != nil {
		t.Errorf("Error getting sample rsa pubkey: %v", err)
		return
	}
	edKey, err := testutils.GetSamplePubKey(keys.EdDSA)
	if err != nil {
		t.Errorf("Error getting sample eddsa pubkey: %v", err)
		return
	}
	badKey := &keys.PubKey{Key: edKey, Alg: "test"}

	type args struct {
		key   *keys.PubKey
		other *keys.PubKey
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"success rsa keys", args{rsaKey, rsaKey2}, true},
		{"error rsa key alg", args{rsaKey, rsaKey3}, false},
		{"error key types", args{rsaKey2, edKey}, false},
		{"error nil key", args{nil, edKey}, false},
		{"error nil other key", args{rsaKey, nil}, false},
		{"error unknown key type", args{badKey, badKey}, false},
		{"success nil keys", args{nil, nil}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.args.key.Equal(tt.args.other)
			if got != tt.want {
				t.Errorf("PubKey.Equal() = %v, wantErr %v", got, tt.want)
			}
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
		{"generate rsa pair", args{keyType: keys.RS256, bits: 2048}, false},
		{"generate es256 pair", args{keyType: keys.ES256}, false},
		{"generate es384 pair", args{keyType: keys.ES384}, false},
		{"generate es512 pair", args{keyType: keys.ES512}, false},
		{"generate edwards curve pair", args{keyType: keys.EdDSA}, false},
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
