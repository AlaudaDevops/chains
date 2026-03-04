/*
Copyright 2023 The Tekton Authors
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package kms creates a signer using a key management server

package kms

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tektoncd/chains/pkg/config"
)

func assertErrorContainsAny(t *testing.T, err error, expectedSubstrings ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error containing one of %v, got nil", expectedSubstrings)
	}
	for _, substr := range expectedSubstrings {
		if strings.Contains(err.Error(), substr) {
			return
		}
	}
	t.Fatalf("expected error to contain one of %v, got %q", expectedSubstrings, err.Error())
}

func TestInValidVaultAddressTimeout(t *testing.T) {
	cfg := config.KMSSigner{}
	cfg.Auth.Address = "http://8.8.8.8:8200"

	_, err := NewSigner(context.Background(), cfg)
	assertErrorContainsAny(t, err,
		"dial tcp 8.8.8.8:8200",
		"no kms provider found for key reference:",
	)
}

func TestInValidVaultAddressConnectionRefused(t *testing.T) {
	cfg := config.KMSSigner{}
	cfg.Auth.Address = "http://127.0.0.1:8200"

	_, err := NewSigner(context.Background(), cfg)
	assertErrorContainsAny(t, err,
		"dial tcp 127.0.0.1:8200",
		"no kms provider found for key reference:",
	)
}

func TestValidVaultAddressConnectionWithoutPortAndScheme(t *testing.T) {
	cfg := config.KMSSigner{}
	cfg.Auth.Address = "abc.com"

	_, err := NewSigner(context.Background(), cfg)
	assertErrorContainsAny(t, err, "no kms provider found for key reference:")
}

func TestValidVaultAddressConnectionWithoutScheme(t *testing.T) {
	cfg := config.KMSSigner{}
	cfg.Auth.Address = "abc.com:80"

	_, err := NewSigner(context.Background(), cfg)
	assertErrorContainsAny(t, err, "no kms provider found for key reference:")
}

func TestValidVaultAddressConnection(t *testing.T) {
	t.Run("Validation for Vault Address with HTTP Url", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := config.KMSSigner{}
		cfg.Auth.Address = server.URL

		_, err := NewSigner(context.Background(), cfg)
		assertErrorContainsAny(t, err, "no kms provider found for key reference:")
	})

	t.Run("Validation for Vault Address with HTTPS URL", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		cfg := config.KMSSigner{}
		cfg.Auth.Address = server.URL

		_, err := NewSigner(context.Background(), cfg)
		assertErrorContainsAny(t, err, "no kms provider found for key reference:")
	})

	t.Run("Validation for Vault Address with Custom Port URL", func(t *testing.T) {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		listener, err := net.Listen("tcp", "127.0.0.1:41227")
		if err != nil {
			t.Fatalf("Failed to create listener: %v", err)
		}

		server.Listener = listener
		server.Start()

		cfg := config.KMSSigner{}
		cfg.Auth.Address = "http://127.0.0.1:41227"

		_, err = NewSigner(context.Background(), cfg)
		assertErrorContainsAny(t, err, "no kms provider found for key reference:")
	})
}
