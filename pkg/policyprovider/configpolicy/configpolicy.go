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

package configpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	re "github.com/ratify-project/ratify/errors"
	"github.com/ratify-project/ratify/pkg/common"
	"github.com/ratify-project/ratify/pkg/executor/types"
	"github.com/ratify-project/ratify/pkg/ocispecs"
	"github.com/ratify-project/ratify/pkg/policyprovider"
	"github.com/ratify-project/ratify/pkg/policyprovider/config"
	pf "github.com/ratify-project/ratify/pkg/policyprovider/factory"
	vt "github.com/ratify-project/ratify/pkg/policyprovider/types"
	"github.com/ratify-project/ratify/pkg/verifier"
)

// PolicyEnforcer describes different polices that are enforced during verification
type PolicyEnforcer struct {
	ArtifactTypePolicies map[string]vt.ArtifactTypeVerifyPolicy
	passthroughEnabled   bool
}

type configPolicyEnforcerConf struct {
	Name                         string                                 `json:"name"`
	ArtifactVerificationPolicies map[string]vt.ArtifactTypeVerifyPolicy `json:"artifactVerificationPolicies,omitempty"`
	PassthroughEnabled           bool                                   `json:"passthroughEnabled"`
}

const (
	defaultPolicyName = "default"
)

type configPolicyFactory struct{}

type verifyResult struct {
	artifactTypeToResult map[string]bool
	mu                   sync.Mutex
}

type verifiedArtifactTypes struct {
	artifactTypes map[string]struct{}
	mu            sync.Mutex
}

func newVerifyResult() *verifyResult {
	return &verifyResult{
		artifactTypeToResult: map[string]bool{},
		mu:                   sync.Mutex{},
	}
}

func newVerifiedArtifactTypes() *verifiedArtifactTypes {
	return &verifiedArtifactTypes{
		artifactTypes: map[string]struct{}{},
		mu:            sync.Mutex{},
	}
}

func (r *verifyResult) set(artifactType string, result bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.artifactTypeToResult[artifactType] = result
}

func (r *verifyResult) get(artifactType string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.artifactTypeToResult[artifactType]
}

func (t *verifiedArtifactTypes) add(artifactType string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.artifactTypes[artifactType] = struct{}{}
}

func (t *verifiedArtifactTypes) exist(artifactType string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.artifactTypes[artifactType]
	return ok
}

// init calls Register for our config policy provider
func init() {
	pf.Register(vt.ConfigPolicy, &configPolicyFactory{})
}

// Create initializes a new policy provider based on the provider selected in config
func (f *configPolicyFactory) Create(policyConfig config.PolicyPluginConfig) (policyprovider.PolicyProvider, error) {
	policyEnforcer := PolicyEnforcer{}

	conf := configPolicyEnforcerConf{}
	policyProviderConfigBytes, err := json.Marshal(policyConfig)
	if err != nil {
		return nil, re.ErrorCodeDataEncodingFailure.NewError(re.PolicyProvider, vt.ConfigPolicy, re.PolicyProviderLink, err, "failed to marshal policy config", re.HideStackTrace)
	}

	if err := json.Unmarshal(policyProviderConfigBytes, &conf); err != nil {
		return nil, re.ErrorCodeDataDecodingFailure.NewError(re.PolicyProvider, vt.ConfigPolicy, re.PolicyProviderLink, err, "failed to unmarshal policy config", re.HideStackTrace)
	}

	if conf.ArtifactVerificationPolicies == nil {
		policyEnforcer.ArtifactTypePolicies = map[string]vt.ArtifactTypeVerifyPolicy{}
	} else {
		policyEnforcer.ArtifactTypePolicies = conf.ArtifactVerificationPolicies
	}
	if policyEnforcer.ArtifactTypePolicies[defaultPolicyName] == "" {
		policyEnforcer.ArtifactTypePolicies[defaultPolicyName] = vt.AllVerifySuccess
	}
	return &policyEnforcer, nil
}

// VerifyNeeded determines if the given subject/reference artifact should be verified
func (enforcer PolicyEnforcer) VerifyNeeded(_ context.Context, _ common.Reference, _ ocispecs.ReferenceDescriptor) bool {
	return true
}

// ContinueVerifyOnFailure determines if the given error can be ignored and verification can be continued.
func (enforcer PolicyEnforcer) ContinueVerifyOnFailure(_ context.Context, _ common.Reference, referenceDesc ocispecs.ReferenceDescriptor, _ types.VerifyResult) bool {
	artifactType := referenceDesc.ArtifactType
	policy := enforcer.ArtifactTypePolicies[artifactType]
	if policy == "" {
		policy = enforcer.ArtifactTypePolicies[defaultPolicyName]
	}
	if policy == vt.AnyVerifySuccess {
		return true
	}
	return false
}

// ErrorToVerifyResult converts an error to a properly formatted verify result
func (enforcer PolicyEnforcer) ErrorToVerifyResult(_ context.Context, subjectRefString string, verifyError error) types.VerifyResult {
	verifierErr := re.ErrorCodeVerifyReferenceFailure.WithDetail(fmt.Sprintf("failed to verify artifact: %s", subjectRefString)).WithError(verifyError)
	errorReport := verifier.NewVerifierResult("", "", "", false, &verifierErr, nil)
	var reports []interface{}
	reports = append(reports, errorReport)
	return types.VerifyResult{IsSuccess: false, VerifierReports: reports}
}

// OverallVerifyResult determines the final outcome of verification that is constructed using the results from
// individual verifications
func (enforcer PolicyEnforcer) OverallVerifyResult(_ context.Context, verifierReports []interface{}) bool {
	if enforcer.passthroughEnabled || len(verifierReports) <= 0 {
		return false
	}
	result := newVerifyResult()
	existingArtifactTypes := newVerifiedArtifactTypes()

	for artifactType, policyType := range enforcer.ArtifactTypePolicies {
		if policyType == vt.AllVerifySuccess {
			result.set(artifactType, true)
		} else {
			result.set(artifactType, false)
		}
	}

	castedVerifierReports := make([]types.NestedVerifierReport, len(verifierReports))
	for i, report := range verifierReports {
		castedReport := report.(types.NestedVerifierReport)
		castedVerifierReports[i] = castedReport
	}

	enforcer.verifyReports(castedVerifierReports, result, existingArtifactTypes)

	// if no artifact types are verified, return false
	if len(existingArtifactTypes.artifactTypes) == 0 {
		return false
	}

	for artifactType, policyType := range enforcer.ArtifactTypePolicies {
		// if default policy is not evaluated, all artifacts should have been evaluated
		// by corresponding policies, just skip the default policy.
		if artifactType == defaultPolicyName && !existingArtifactTypes.exist(defaultPolicyName) {
			continue
		}
		if policyType == vt.AnyVerifySuccess {
			if !result.get(artifactType) {
				return false
			}
		} else {
			if !result.get(artifactType) || !existingArtifactTypes.exist(artifactType) {
				return false
			}
		}
	}

	return true
}

// GetPolicyType returns the type of the policy.
func (enforcer PolicyEnforcer) GetPolicyType(_ context.Context) string {
	return vt.ConfigPolicy
}

func (enforcer PolicyEnforcer) verifyReports(verifierReports []types.NestedVerifierReport, result *verifyResult, existingArtifactTypes *verifiedArtifactTypes) {
	wg := sync.WaitGroup{}
	for _, report := range verifierReports {
		report := report
		if len(report.VerifierReports) == 0 {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			existingArtifactTypes.add(report.ArtifactType)

			// extract the policy for the artifact type of the verified artifact if specified
			artifactType := report.ArtifactType
			policyType, ok := enforcer.ArtifactTypePolicies[report.ArtifactType]
			// if artifact type policy not specified, set policy to be default policy and add artifact type to success map
			if !ok {
				policyType = enforcer.ArtifactTypePolicies[defaultPolicyName]
				artifactType = defaultPolicyName
			}
			existingArtifactTypes.add(artifactType)

			for _, verifierReport := range report.VerifierReports {
				if policyType == vt.AnyVerifySuccess {
					if verifierReport.IsSuccess {
						result.set(artifactType, true)
					}
				} else {
					if !verifierReport.IsSuccess {
						result.set(artifactType, false)
					}
				}
			}

			enforcer.verifyReports(report.NestedReports, result, existingArtifactTypes)
		}()
	}
	wg.Wait()
}
