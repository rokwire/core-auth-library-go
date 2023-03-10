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

package authutils_test

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/rokwire/core-auth-library-go/v3/authutils"
)

func TestHashSha256(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		wantHex string
		wantErr bool
	}{
		{"found", args{[]byte("This is a test.")}, "a8a2f6ebe286697c527eb35a58b5539532e9b3ae3b64d4eb0a46fb657b41562c", false},
		{"empty", args{[]byte{}}, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false},
		{"nil", args{nil}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := authutils.HashSha256(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashSha256() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			var want []byte
			if tt.wantHex != "" {
				want, err = hex.DecodeString(tt.wantHex)
				if err != nil {
					t.Errorf("error decoding test want hex: %s", tt.wantHex)
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("HashSha256() = %v, want %v", got, want)
			}
		})
	}
}

func TestContainsString(t *testing.T) {
	type args struct {
		slice []string
		val   string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"return true when found", args{[]string{"test1", "test2", "test3"}, "test2"}, true},
		{"return false when not found", args{[]string{"test1", "test2", "test3"}, "test5"}, false},
		{"return false on partial match", args{[]string{"test1", "test2", "test3"}, "test"}, false},
		{"return false on nil slice", args{nil, "test"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authutils.ContainsString(tt.args.slice, tt.args.val); got != tt.want {
				t.Errorf("ContainsString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRemoveString(t *testing.T) {
	type args struct {
		slice []string
		val   string
	}
	tests := []struct {
		name  string
		args  args
		want  []string
		want1 bool
	}{
		{"return modified list, true when found", args{[]string{"test1", "test2", "test3"}, "test2"}, []string{"test1", "test3"}, true},
		{"return unmodified list, false when not found", args{[]string{"test1", "test2", "test3"}, "test5"}, []string{"test1", "test2", "test3"}, false},
		{"return unmodified list, false on partial match", args{[]string{"test1", "test2", "test3"}, "test"}, []string{"test1", "test2", "test3"}, false},
		{"return nil, false on nil slice", args{nil, "test"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := authutils.RemoveString(tt.args.slice, tt.args.val)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RemoveString() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("RemoveString() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestReadResponseBody(t *testing.T) {
	unauthorized := &http.Response{StatusCode: http.StatusUnauthorized, Status: fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), Body: io.NopCloser(strings.NewReader("test"))}
	ok := &http.Response{StatusCode: http.StatusOK, Status: fmt.Sprintf("%d %s", http.StatusOK, http.StatusText(http.StatusOK)), Body: io.NopCloser(strings.NewReader("test"))}

	type args struct {
		resp *http.Response
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"return error on nil response", args{nil}, nil, true},
		{"return error on bad status code", args{unauthorized}, []byte("test"), true},
		{"return body", args{ok}, []byte("test"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := authutils.ReadResponseBody(tt.args.resp)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadResponseBody() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if string(got) != string(tt.want) {
				t.Errorf("ReadResponseBody() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	type args struct {
		n int
	}
	tests := []struct {
		name    string
		args    args
		wantLen int
		wantErr bool
	}{
		{"success", args{32}, 32, false},
		{"zero length", args{0}, 0, false},
		{"negative length", args{-1}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := authutils.GenerateRandomBytes(tt.args.n)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateRandomBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) != tt.wantLen {
				t.Errorf("GenerateRandomBytes() = %v, want %v", len(got), tt.wantLen)
			}
		})
	}
}
