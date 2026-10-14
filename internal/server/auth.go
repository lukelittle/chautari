/**
 * Copyright 2026 the original author or authors from the Chautari project.
 *
 * This file is part of the Chautari project, see https://github.com/lukelittle/chautari
 * for more information.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"strings"

	"github.com/lukelittle/chautari/internal/estate"
	"github.com/lukelittle/chautari/internal/store"
)

// KeyPrefix starts every Chautari API key.
const KeyPrefix = "ck_"

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// NewKeySecret returns a fresh API key: ck_ + 43 base62 characters (~256 bits).
func NewKeySecret() string {
	var b strings.Builder
	b.WriteString(KeyPrefix)
	max := big.NewInt(int64(len(base62)))
	for i := 0; i < 43; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err) // the system RNG failing is not recoverable
		}
		b.WriteByte(base62[n.Int64()])
	}
	return b.String()
}

// HashKey is how keys are stored and looked up.
func HashKey(secret string) string {
	s := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(s[:])
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if k := r.Header.Get("X-Api-Key"); k != "" {
		return k
	}
	return ""
}

// caller is an authenticated application.
type caller struct {
	key  store.Key
	app  estate.App
	team estate.Team
}

var errUnauthorized = errors.New("missing or invalid API key")

// authenticate resolves the request's API key to an app and team.
func (s *Server) authenticate(ctx context.Context, r *http.Request, rt *runtime) (caller, error) {
	secret := bearer(r)
	if !strings.HasPrefix(secret, KeyPrefix) {
		return caller{}, errUnauthorized
	}
	k, err := s.cfg.Store.KeyByHash(ctx, HashKey(secret))
	if errors.Is(err, store.ErrNotFound) || (err == nil && !k.Active()) {
		return caller{}, errUnauthorized
	}
	if err != nil {
		return caller{}, err
	}
	app, ok := rt.estate.App(k.App)
	if !ok {
		return caller{}, errors.New("key belongs to an app no longer in the estate")
	}
	team, ok := rt.estate.Team(app.Team)
	if !ok {
		return caller{}, errors.New("key belongs to a team no longer in the estate")
	}
	return caller{key: k, app: app, team: team}, nil
}
