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
	"time"
)

type Minter struct {
	// Max TTL
	ttl time.Duration
	// Token provider
	provider Provider
	// Time provider
	time Time
	// Cookie crypto settings
	crypto Crypto
	// Signer cookie signing
	signer Signer
}

type Session interface {
	Domain() string
	User()   string
	Groups() []string
}

func (m *Minter) Create(s Session) ([]byte, error) {
	expiry := m.time.Now().Add(m.ttl)

	req := Request{}
	req.Domain = s.Domain()
	req.User = s.User()
	req.Groups = s.Groups()
	req.Expiry = expiry

	cookie := Cookie{}
	cookie.Version = "v1"
	token, err := m.provider.New(req)
	if err != nil {
		return nil, err
	}

	cookie.Token = token

	b, err := json.Marshal(cookie)
	if err != nil {
		return nil, err
	}

	p := ProtectedCookie{}
	p.Cookie = m.crypto.Encrypt(b)
	p.Sig = m.signer.Sign(p.Cookie)

	v, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func NewMinter(ttl time.Duration, c Crypto, s Signer, p Provider, t Time) *Minter {
	m := Minter{}
	m.ttl = ttl
	m.signer = s
	m.provider = p
	m.crypto = c
	m.time = t
	return &m
}
