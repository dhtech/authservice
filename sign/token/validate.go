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
	"encoding/json"
	"errors"
	"fmt"
)

type Validator struct {
	// Token provider
	provider Provider
	// Time provider
	time Time
	// Cookie crypto
	crypto Crypto
	// Cookie verification
	verifier Verifier
}

func (v *Validator) Validate(d []byte, domain string, group string) (*Request, error) {
	var p ProtectedCookie
	err := json.Unmarshal(d, &p)
	if err != nil {
		return nil, err
	}
	if !v.verifier.Verify(p.Cookie, p.Sig) {
		return nil, errors.New("verification failed")
	}
	b, err := v.crypto.Decrypt(p.Cookie)
	if err != nil {
		return nil, err
	}
	var c Cookie
	err = json.Unmarshal(b, &c)
	if err != nil {
		return nil, err
	}

	if c.Version != "v1" {
		return nil, fmt.Errorf("unknown version: %s", c.Version)
	}

	pr := v.provider
	if pr == nil {
		return nil, errors.New("provider not found")
	}
	return pr.Validate(c.Token, domain, group)
}

func NewValidator(c Crypto, ve Verifier, p Provider, t Time) *Validator {
	v := Validator{}
	v.provider = p
	v.crypto = c
	v.verifier = ve
	v.time = t
	return &v
}
