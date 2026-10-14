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

package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetupIsNoopWithoutEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	shutdown, err := Setup(context.Background(), "chautari", "test")
	if err != nil {
		t.Fatal(err)
	}
	shutdown(context.Background())
}

// Regression: merging resources with different semconv schema URLs failed at
// startup, which only showed up once a collector was configured.
func TestSetupWithEndpoint(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer collector.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", collector.URL)
	t.Setenv("OTEL_SERVICE_NAME", "chautari-test")
	shutdown, err := Setup(context.Background(), "chautari", "test")
	if err != nil {
		t.Fatal(err)
	}
	h := Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }), "test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
