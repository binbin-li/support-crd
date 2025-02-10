/*
Copyright The Ratify Authors.
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

package ratifyserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/ratify-project/ratify-go"
	"github.com/ratify-project/ratify/server/config"
	"github.com/sirupsen/logrus"
)

const (
	ServerRootURL = "/ratify/gatekeeper/v2"
)

var tlsCert atomic.Value

type Server struct {
	Address              string
	certFile             string
	keyFile              string
	Router               *mux.Router
	Executor             ratify.Executor
	VerifyRequestTimeout time.Duration
}
type ServerOptions struct {
	ConfigFilePath    string
	HTTPServerAddress string
}

func StartServer(opts *ServerOptions) {
	cf, err := config.Load(opts.ConfigFilePath)
	if err != nil {
		logrus.Errorf("Failed to load configuration: %v", err)
		os.Exit(1)
	}

	server, err := NewServer(cf)
	if err != nil {
		logrus.Errorf("Failed to create server: %v", err)
		os.Exit(1)
	}

	logrus.Infof("starting server at %s", opts.HTTPServerAddress)
	if err := server.Run(); err != nil {
		logrus.Errorf("Failed to start server: %v", err)
		os.Exit(1)
	}
}

func NewServer(config *config.Config) (*Server, error) {
	server := &Server{
		Router:  mux.NewRouter(),
		Address: config.Address,
	}
	if err := server.registerHandlers(); err != nil {
		return nil, fmt.Errorf("failed to register handlers: %w", err)
	}
	return server, nil
}

func (s *Server) Run() error {
	srv := &http.Server{
		Addr:         s.Address,
		Handler:      s.Router,
		WriteTimeout: 5 * time.Second,
		ReadTimeout:  5 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		if s.certFile != "" && s.keyFile != "" {
			logrus.Infof("starting server with TLS at %s", s.Address)
			if err := loadCertificate(s.certFile, s.keyFile); err != nil {
				logrus.Errorf("failed to load certificate: %v", err)
				return
			}
			srv.TLSConfig = &tls.Config{
				MinVersion:     tls.VersionTLS13,
				GetCertificate: getCertificate,
			}
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				logrus.Errorf("failed to start server: %v", err)
			}
		} else {
			logrus.Infof("starting server at %s", s.Address)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logrus.Errorf("failed to start server: %v", err)
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logrus.Errorf("failed to shutdown server: %v", err)
		return err
	}
	return nil
}

func loadCertificate(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}
	tlsCert.Store(&cert)
	return nil
}

func getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cert := tlsCert.Load(); cert != nil {
		return cert.(*tls.Certificate), nil
	}
	return nil, nil
}

func (s *Server) registerHandlers() error {
	return s.registerVerifyHandler()
}

func (s *Server) registerVerifyHandler() error {
	verifyPath, err := url.JoinPath(ServerRootURL, "verify")
	if err != nil {
		return err
	}
	s.Router.Methods(http.MethodPost).Path(verifyPath).Handler(middlewareWithTimeout(s.verifyHandler(), s.VerifyRequestTimeout))
	return nil
}

func (s *Server) verifyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.verify(r.Context(), w, r)
	}
}

func (s *Server) verify(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	defer r.Body.Close()

	var providerRequest externaldata.ProviderRequest
	if err = json.Unmarshal(body, &providerRequest); err != nil {
		return fmt.Errorf("failed to unmarshal request body: %w", err)
	}

	var results []externaldata.Item
	for _, key := range providerRequest.Request.Keys {
		item := externaldata.Item{
			Key: key,
		}
		opts := ratify.ValidateArtifactOptions{
			Subject: key,
		}
		result, err := s.Executor.ValidateArtifact(ctx, opts)
		if err != nil {
			item.Error = err.Error()
		}
		item.Value = result
		results = append(results, item)
	}

	response := externaldata.ProviderResponse{
		APIVersion: "externaldata.gatekeeper.sh/v1alpha1",
		Kind:       "ProviderResponse",
		Response: externaldata.Response{
			Items: results,
		},
	}
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(response)
}

func middlewareWithTimeout(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
