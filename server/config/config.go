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

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ratify-project/ratify/pkg/homedir"
)

const (
	ConfigFileName = "config.json"
	ConfigFileDir  = ".ratify"
)

var (
	initConfigDir         = new(sync.Once)
	configDir             string
	defaultConfigFilePath string
	homeDir               string
)

type VerifierOptions struct{}

type StoreOptions struct{}

type PolicyEnforcerOptions struct{}

type ExecutorConfig struct{}

type Config struct {
	Verifiers       []VerifierOptions       `json:"verifiers,omitempty"`
	Stores          []StoreOptions          `json:"stores,omitempty"`
	PolicyEnforcers []PolicyEnforcerOptions `json:"policyEnforcers,omitempty"`
	Executor        ExecutorConfig          `json:"executor,omitempty"`
	Address         string                  `json:"address,omitempty"`
}

func InitDefaultPaths() {
	if configDir != "" {
		return
	}
	configDir = os.Getenv("RATIFY_CONFIG")
	if configDir == "" {
		configDir = filepath.Join(getHomeDir(), ConfigFileDir)
	}
	defaultConfigFilePath = filepath.Join(configDir, ConfigFileName)
}

func Load(configPath string) (*Config, error) {
	body, err := os.ReadFile(getConfigurationFile(configPath))
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	config := &Config{}
	if err = json.Unmarshal(body, config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	return config, nil
}

func getConfigurationFile(configFilePath string) string {
	if configFilePath == "" {
		if configDir == "" {
			initConfigDir.Do(InitDefaultPaths)
		}
		return defaultConfigFilePath
	}
	return configFilePath
}

func getHomeDir() string {
	if homeDir == "" {
		homeDir = homedir.Get()
	}
	return homeDir
}
