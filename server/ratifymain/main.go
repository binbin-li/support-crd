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

package ratifymain

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/ratify-project/ratify/config"
	"github.com/ratify-project/ratify/httpserver"
	"github.com/ratify-project/ratify/internal/logger"
	"github.com/ratify-project/ratify/pkg/cache"
	"github.com/ratify-project/ratify/pkg/manager"
	"github.com/sirupsen/logrus"

	_ "github.com/ratify-project/ratify/pkg/cache/dapr"                  // register dapr cache
	_ "github.com/ratify-project/ratify/pkg/cache/ristretto"             // register ristretto cache
	_ "github.com/ratify-project/ratify/pkg/policyprovider/configpolicy" // register configpolicy policy provider
	_ "github.com/ratify-project/ratify/pkg/policyprovider/regopolicy"   // register regopolicy policy provider
	_ "github.com/ratify-project/ratify/pkg/referrerstore/oras"          // register oras referrer store
	_ "github.com/ratify-project/ratify/pkg/verifier/cosign"             // register cosign verifier
	_ "github.com/ratify-project/ratify/pkg/verifier/notation"           // register notation verifier
)

// options defines the command line options to start the ratify server.
type options struct {
	configFilePath    string
	httpServerAddress string
	certDirectory     string
	caCertFile        string
	enableCrdManager  bool
	cacheEnabled      bool
	cacheType         string
	cacheName         string
	cacheSize         int
	cacheTTL          time.Duration
	metricsEnabled    bool
	metricsType       string
	metricsPort       int
	healthPort        string
}

func Main() {
	opts := parse()
	if err := startRatify(opts); err != nil {
		logrus.Errorf("Error starting Ratify: %v", err)
	}
}

// parse parses the command line arguments and returns the options.
func parse() *options {
	opts := options{}
	flag.StringVar(&opts.httpServerAddress, "http", "", "HTTP Address")
	flag.StringVar(&opts.configFilePath, "config", "", "Config File Path")
	flag.StringVar(&opts.certDirectory, "cert-dir", "", "Path to ratify certs")
	flag.StringVar(&opts.caCertFile, "ca-cert-file", "", "Path to CA cert file")
	flag.BoolVar(&opts.enableCrdManager, "enable-crd-manager", false, "Start crd manager if enabled (default: false)")
	flag.BoolVar(&opts.cacheEnabled, "cache-enabled", false, "Enable cache if enabled (default: false)")
	flag.StringVar(&opts.cacheType, "cache-type", cache.DefaultCacheType, fmt.Sprintf("Cache type to use (default: %s)", cache.DefaultCacheType))
	flag.StringVar(&opts.cacheName, "cache-name", cache.DefaultCacheName, fmt.Sprintf("Cache implementation name to use (default: %s)", cache.DefaultCacheName))
	flag.IntVar(&opts.cacheSize, "cache-size", cache.DefaultCacheSize, fmt.Sprintf("Cache max size to use in MB (default: %d)", cache.DefaultCacheSize))
	flag.DurationVar(&opts.cacheTTL, "cache-ttl", cache.DefaultCacheTTL, fmt.Sprintf("Cache TTL for the verifier http server (default: %fs)", cache.DefaultCacheTTL.Seconds()))
	flag.BoolVar(&opts.metricsEnabled, "metrics-enabled", false, "Enable metrics exporter if enabled (default: false)")
	flag.StringVar(&opts.metricsType, "metrics-type", httpserver.DefaultMetricsType, fmt.Sprintf("Metrics exporter type to use (default: %s)", httpserver.DefaultMetricsType))
	flag.IntVar(&opts.metricsPort, "metrics-port", httpserver.DefaultMetricsPort, fmt.Sprintf("Metrics exporter port to use (default: %d)", httpserver.DefaultMetricsPort))
	flag.StringVar(&opts.healthPort, "health-port", httpserver.DefaultHealthPort, fmt.Sprintf("Health port to use (default: %s)", httpserver.DefaultHealthPort))
	flag.Parse()

	logrus.Infof("Starting Ratify: %+v", opts)
	return &opts
}

// startRatify starts the ratify server.
func startRatify(opts *options) error {
	if opts.cacheEnabled {
		// initialize global cache of specified type
		if _, err := cache.NewCacheProvider(context.TODO(), opts.cacheType, opts.cacheName, opts.cacheSize); err != nil {
			return fmt.Errorf("error initializing cache of type %s: %w", opts.cacheType, err)
		}
		logrus.Debugf("initialized cache of type %s", opts.cacheType)
	}
	logConfig, err := config.GetLoggerConfig(opts.configFilePath)
	if err != nil {
		return fmt.Errorf("failed to retrieve logger configuration: %w", err)
	}
	if err := logger.InitLogConfig(logConfig); err != nil {
		return fmt.Errorf("failed to initialize logger configuration: %w", err)
	}

	// in crd mode, the manager gets latest store/verifier from crd and pass on to the http server
	if opts.enableCrdManager {
		certRotatorReady := make(chan struct{})
		logrus.Infof("starting crd manager")
		go manager.StartManager(certRotatorReady, opts.healthPort)
		manager.StartServer(opts.httpServerAddress, opts.configFilePath, opts.certDirectory, opts.caCertFile, opts.cacheTTL, opts.metricsEnabled, opts.metricsType, opts.metricsPort, certRotatorReady)

		return nil
	}

	getExecutor, err := config.GetExecutorAndWatchForUpdate(opts.configFilePath)
	if err != nil {
		return err
	}

	if opts.httpServerAddress != "" {
		server, err := httpserver.NewServer(context.Background(), opts.httpServerAddress, getExecutor, opts.certDirectory, opts.caCertFile, opts.cacheTTL, opts.metricsEnabled, opts.metricsType, opts.metricsPort)
		if err != nil {
			return err
		}
		logrus.Infof("starting server at: %s", opts.httpServerAddress)
		if err := server.Run(nil); err != nil {
			return err
		}
	}

	return nil
}
