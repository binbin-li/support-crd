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

package core

import (
	"context"
	"errors"
	"sync"

	re "github.com/ratify-project/ratify/errors"
	"github.com/ratify-project/ratify/pkg/executor"
	ec "github.com/ratify-project/ratify/pkg/executor/core"
	"github.com/ratify-project/ratify/pkg/executor/types"
)

type Ratify struct {
	mu       sync.RWMutex
	executor executor.Executor
}

type ExecutorConfig struct {
}

var emptyExecutorConfig = ExecutorConfig{}

func NewRatify() *Ratify {
	return &Ratify{}
}

func (r *Ratify) Validate(ctx context.Context, artifactReference string, opts ValidatorOption) (types.VerifyResult, error) {
	r.mu.Lock()
	defer r.mu.RUnlock()

	if r.executor == nil {
		return types.VerifyResult{}, re.ErrExecutorNotInitialized
	}

	verifyParams := executor.VerifyParameters{
		Subject: artifactReference,
	}
	return r.executor.VerifySubject(ctx, verifyParams)
}

func (r *Ratify) UpdateExecutor(newExecutor executor.Executor) error {
	if newExecutor == nil {
		return errors.New("executor cannot be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	r.executor = newExecutor
	return nil
}

func (r *Ratify) UpdateExecutorByConfig(config ExecutorConfig) error {
	executor, err := NewExecutor(config)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.executor = executor
	return nil
}

func (r *Ratify) PatchUpdateExecutorByConfig(config ExecutorConfig) error {
	executor, err := NewExecutor(config)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.executor = executor
	return nil
}

func NewExecutor(config ExecutorConfig) (executor.Executor, error) {
	if config == emptyExecutorConfig {
		return nil, errors.New("config cannot be empty")
	}
	return ec.Executor{}, nil
}
