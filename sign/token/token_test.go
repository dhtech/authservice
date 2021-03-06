//
// Copyright 2017 Tink AB
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type FakeCrypto struct{}
type FakeSigner struct{}
type FakeVerifier struct{}

func (c *FakeCrypto) Encrypt(b []byte) []byte {
	return b
}

func (c *FakeCrypto) Decrypt(b []byte) ([]byte, error) {
	if strings.Contains(string(b), "fail-decrypt") {
		return nil, errors.New("decrypt failed")
	}
	return b, nil
}

func (s *FakeSigner) Sign(d []byte) []byte {
	return []byte{byte(len(d))}
}

func (v *FakeVerifier) Verify(d []byte, s []byte) bool {
	if len(s) != 1 {
		panic("len of signature is not 1")
	}
	return s[0] == byte(len(d))
}

type FakeTokenProvider struct{}

func (p *FakeTokenProvider) New(req Request) ([]byte, error) {
	return []byte("test-token"), nil
}

func (p *FakeTokenProvider) Validate(b []byte, d string, g string) (*Request, error) {
	if string(b) != "test-token" {
		return nil, errors.New("invalid token")
	}
	r := Request{}
	r.User = "test-user"
	return &r, nil
}

func NewTestMinter() *Minter {
	ftp := FakeTokenProvider{}
	t := FakeTime{}
	c := FakeCrypto{}
	s := FakeSigner{}
	return NewMinter(time.Minute, &c, &s, &ftp, &t)
}

func NewTestValidator() *Validator {
	ftp := FakeTokenProvider{}
	t := FakeTime{}
	c := FakeCrypto{}
	v := FakeVerifier{}
	return NewValidator(&c, &v, &ftp, &t)
}

func NewTestRequest(ver string, t string) []byte {
	cs := Cookie{
		Version:  ver,
		Token:    []byte(t),
	}
	v, _ := json.Marshal(cs)
	pc := ProtectedCookie{
		Cookie: v,
		Sig: []byte{byte(len(v))},
	}
	pv, _ := json.Marshal(pc)
	return pv
}

func TestCreate(t *testing.T) {
	// TODO
}

type FakeSession struct {
}

func (s *FakeSession) User() string {
	return "dummy-user"
}

func (s *FakeSession) Domain() string {
	return "test-domain"
}

func (s *FakeSession) Groups() []string {
	return []string{"a-group", "test-group"}
}

func TestCreateValidate(t *testing.T) {
	m := NewTestMinter()
	v := NewTestValidator()

	s := FakeSession{}
	c, err := m.Create(&s)
	assert.NoError(t, err)

	u, err := v.Validate(c, "test-domain", "test-group")
	assert.NoError(t, err)
	assert.Equal(t, "test-user", u.User)
}

func TestValidateSuccess(t *testing.T) {
	v := NewTestValidator()

	// Successful token
	r := NewTestRequest("v1", "test-token")
	u, err := v.Validate(r, "test-domain", "test-group")
	assert.NoError(t, err)
	assert.Equal(t, "test-user", u.User)
}

func TestValidateInvalidToken(t *testing.T) {
	v := NewTestValidator()
	// Invalid token
	r := NewTestRequest("v1", "invalid-token")
	_, err := v.Validate(r, "test-domain", "test-group")
	assert.Error(t, err)
}

func TestValidateNoToken(t *testing.T) {
	v := NewTestValidator()

	// No token
	r := []byte{}
	_, err := v.Validate(r, "test-domain", "test-group")
	assert.Error(t, err)
}

func TestValidateCorruptToken(t *testing.T) {
	v := NewTestValidator()

	// Corrupt token (base64)
	r := []byte("****")
	_, err := v.Validate(r, "test-domain", "test-group")
	assert.Error(t, err)
}

func TestValidateCorruptTokenJSON(t *testing.T) {
	v := NewTestValidator()

	// Corrupt token (json)
	r := []byte(base64.URLEncoding.EncodeToString([]byte("{1:2}")))
	_, err := v.Validate(r, "test-domain", "test-group")
	assert.Error(t, err)
}

func TestValidateInvalidVersion(t *testing.T) {
	v := NewTestValidator()

	// Invalid version
	r := NewTestRequest("v2", "")
	_, err := v.Validate(r, "test-domain", "test-group")
	assert.EqualError(t, err, "unknown version: v2")
}

func TestValidateInvalidSignature(t *testing.T) {
	v := NewTestValidator()

	// Invalid signature
	r := []byte("{\"Sig\": \"Nw==\"}")
	_, err := v.Validate(r, "test-domain", "test-group")
	assert.EqualError(t, err, "verification failed")
}

func TestValidateFailedDecrypt(t *testing.T) {
	v := NewTestValidator()

	// Fail decrypt
	r := NewTestRequest("fail-decrypt", "")
	_, err := v.Validate(r, "test-domain", "test-group")
	assert.EqualError(t, err, "decrypt failed")
}
