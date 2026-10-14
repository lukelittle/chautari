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

// Package telemetry wires OpenTelemetry tracing. It is a no-op unless
// OTEL_EXPORTER_OTLP_ENDPOINT is set, so tests and laptops need nothing.
package telemetry

import (
	"context"
	"net/http"
	"os"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Setup installs a tracer provider exporting OTLP over HTTP and returns a
// shutdown function. The exporter reads the standard OTEL_* variables.
func Setup(ctx context.Context, service, version string) (func(context.Context) error, error) {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" {
		return func(context.Context) error { return nil }, nil
	}
	exp, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, err
	}
	// Schemaless, so it never conflicts with the SDK default resource's
	// schema version; OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES still win.
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName(service), semconv.ServiceVersion(version)))
	if err != nil {
		return nil, err
	}
	if env, err := resource.New(ctx, resource.WithFromEnv()); err == nil {
		if merged, err := resource.Merge(res, env); err == nil {
			res = merged
		}
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	return tp.Shutdown, nil
}

// Handler wraps an http.Handler with server spans.
func Handler(h http.Handler, name string) http.Handler {
	return otelhttp.NewHandler(h, name, otelhttp.WithFilter(func(r *http.Request) bool {
		return r.URL.Path != "/healthz" && r.URL.Path != "/readyz"
	}))
}

// Transport wraps a RoundTripper with client spans and trace propagation, so
// a request's trace continues into the data plane.
func Transport(rt http.RoundTripper) http.RoundTripper {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return otelhttp.NewTransport(rt)
}
