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
	"errors"
	"flag"

	"github.com/ratify-project/ratify/server/ratifyserver"
	"github.com/sirupsen/logrus"
)

type options struct {
	configFilePath    string
	httpServerAddress string
}

func Main() {
	opts := parse()
	if err := startRatify(opts); err != nil {
		logrus.Errorf("Failed to start Ratify: %v", err)
		panic(err)
	}
}

func parse() *options {
	opts := &options{}
	flag.StringVar(&opts.configFilePath, "config", "", "Path to the Ratify configuration file")
	flag.StringVar(&opts.httpServerAddress, "http", "", "HTTP server address")

	logrus.Infof("Starting Ratify: %+v", opts)
	return opts
}

func startRatify(opts *options) error {
	if len(opts.httpServerAddress) == 0 {
		return errors.New("HTTP server address is required")
	}
	if opts.httpServerAddress != "" {
		server, err := ratifyserver.NewServer()
		if err != nil {
			return err
		}
		logrus.Infof("Starting HTTP server at %s", opts.httpServerAddress)
		if err := server.Run(); err != nil {
			return err
		}
	}
	return nil
}
