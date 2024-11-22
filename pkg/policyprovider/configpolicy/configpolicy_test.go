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
	"testing"

	oci "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/ratify-project/ratify/pkg/common"
	et "github.com/ratify-project/ratify/pkg/executor/types"
	"github.com/ratify-project/ratify/pkg/ocispecs"
	pc "github.com/ratify-project/ratify/pkg/policyprovider/config"
	pf "github.com/ratify-project/ratify/pkg/policyprovider/factory"
	"github.com/ratify-project/ratify/pkg/policyprovider/types"
	vr "github.com/ratify-project/ratify/pkg/verifier"
)

func TestPolicyEnforcer_ContinueVerifyOnFailure(t *testing.T) {
	configPolicyConfig := map[string]interface{}{
		"name": "configPolicy",
		"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{
			"application/vnd.cncf.notary.signature": "any",
			"application/spdx+json":                 "all",
			"default":                               "any",
		},
	}
	config := pc.PoliciesConfig{
		Version:      "1.0.0",
		PolicyPlugin: configPolicyConfig,
	}

	policyEnforcer, err := pf.CreatePolicyProviderFromConfig(config)

	if err != nil {
		t.Fatalf("PolicyEnforcer should create from PoliciesConfig")
	}

	ctx := context.Background()
	subjectReference := common.Reference{
		Path:     "",
		Digest:   "",
		Tag:      "",
		Original: "",
	}
	referenceDesc := ocispecs.ReferenceDescriptor{
		Descriptor:   oci.Descriptor{},
		ArtifactType: "application/vnd.cncf.notary.signature",
	}
	result := et.VerifyResult{
		IsSuccess:       false,
		VerifierReports: nil,
	}

	check := policyEnforcer.ContinueVerifyOnFailure(ctx, subjectReference, referenceDesc, result)

	if check != true {
		t.Fatalf("For policy of 'any' PolicyEnforcer should allow continuing on verify failure")
	}

	referenceDesc.ArtifactType = "application/spdx+json"

	check = policyEnforcer.ContinueVerifyOnFailure(ctx, subjectReference, referenceDesc, result)

	if check != false {
		t.Fatalf("For policy 'all' PolicyEnforcer should not allow continuing on verify failure")
	}

	referenceDesc.ArtifactType = "unknown"

	check = policyEnforcer.ContinueVerifyOnFailure(ctx, subjectReference, referenceDesc, result)

	if check != true {
		t.Fatalf("For artifact types without a policy the default policy should be followed")
	}
}

func TestPolicyEnforcer_OverallVerifyResult(t *testing.T) {
	testcases := []struct {
		name               string
		configPolicyConfig map[string]interface{}
		verifierReports    []interface{}
		output             bool
	}{
		{
			name: "no artifact policies and no referres",
			configPolicyConfig: map[string]interface{}{
				"name":                         "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{},
			},
			verifierReports: []interface{}{},
			output:          false,
		},
		{
			name: "no artifact policies and no matching verifier reports",
			configPolicyConfig: map[string]interface{}{
				"name":                         "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{},
			},
			verifierReports: []interface{}{
				et.NestedVerifierReport{
					Subject:      "",
					ArtifactType: "application/vnd.cncf.notary.signature",
				},
			},
			output: false,
		},
		{
			name: "no artifact policies and 1 verifier result is false",
			configPolicyConfig: map[string]interface{}{
				"name":                         "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{},
			},
			verifierReports: []interface{}{
				et.NestedVerifierReport{
					Subject:      "",
					ArtifactType: "application/vnd.cncf.notary.signature",
					VerifierReports: []vr.VerifierResult{
						{
							IsSuccess: true,
						},
						{
							IsSuccess: false,
						},
					},
				},
			},
			output: false,
		},
		{
			name: "no artifact policies but default relaxed to 'any' and 1 verifier result is false",
			configPolicyConfig: map[string]interface{}{
				"name": "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{
					"default": "any",
				},
			},
			verifierReports: []interface{}{
				et.NestedVerifierReport{
					Subject:      "",
					ArtifactType: "application/vnd.cncf.notary.signature",
					VerifierReports: []vr.VerifierResult{
						{
							IsSuccess: true,
						},
						{
							IsSuccess: false,
						},
					},
				},
			},
			output: true,
		},
		{
			name: "any notation artifact policy but no artifact verifier reports",
			configPolicyConfig: map[string]interface{}{
				"name": "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{
					"application/vnd.cncf.notary.signature": "any",
				},
			},
			verifierReports: []interface{}{},
			output:          false,
		},
		{
			name: "any notation artifact policy and 1 success notation report",
			configPolicyConfig: map[string]interface{}{
				"name": "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{
					"application/vnd.cncf.notary.signature": "any",
				},
			},
			verifierReports: []interface{}{
				et.NestedVerifierReport{
					Subject:      "",
					ArtifactType: "application/vnd.cncf.notary.signature",
					VerifierReports: []vr.VerifierResult{
						{
							IsSuccess: true,
						},
						{
							IsSuccess: false,
						},
					},
				},
			},
			output: true,
		},
		{
			name: "all notation artifact policy and 1 success notation report",
			configPolicyConfig: map[string]interface{}{
				"name": "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{
					"application/vnd.cncf.notary.signature": "all",
				},
			},
			verifierReports: []interface{}{
				et.NestedVerifierReport{
					Subject:      "",
					ArtifactType: "application/vnd.cncf.notary.signature",
					VerifierReports: []vr.VerifierResult{
						{
							IsSuccess: true,
						},
						{
							IsSuccess: false,
						},
					},
				},
			},
			output: false,
		},
		{
			name: "all notation artifact policy and both notation reports are true",
			configPolicyConfig: map[string]interface{}{
				"name": "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{
					"application/vnd.cncf.notary.signature": "all",
				},
			},
			verifierReports: []interface{}{
				et.NestedVerifierReport{
					Subject:      "",
					ArtifactType: "application/vnd.cncf.notary.signature",
					VerifierReports: []vr.VerifierResult{
						{
							IsSuccess: true,
						},
						{
							IsSuccess: true,
						},
					},
				},
			},
			output: true,
		},
		{
			// any notation artifact policy, any sbom artifact policy and notation report is true and sbom is false
			name: "any notation artifact policy, any sbom artifact policy and notation report is true and sbom is false",
			configPolicyConfig: map[string]interface{}{
				"name": "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{
					"application/vnd.cncf.notary.signature": "any",
					"application/spdx+json":                 "any",
				},
			},
			verifierReports: []interface{}{
				et.NestedVerifierReport{
					Subject:      "",
					ArtifactType: "application/vnd.cncf.notary.signature",
					VerifierReports: []vr.VerifierResult{
						{
							IsSuccess: true,
						},
					},
				},
				et.NestedVerifierReport{
					Subject:      "",
					ArtifactType: "application/spdx+json",
					VerifierReports: []vr.VerifierResult{
						{
							IsSuccess: false,
						},
					},
				},
			},
			output: false,
		},
		{
			// any notation artifact policy, all sbom artifact policy, and both notation and sbom are true
			configPolicyConfig: map[string]interface{}{
				"name": "configPolicy",
				"artifactVerificationPolicies": map[string]types.ArtifactTypeVerifyPolicy{
					"application/vnd.cncf.notary.signature": "any",
					"application/spdx+json":                 "all",
				},
			},
			verifierReports: []interface{}{
				et.NestedVerifierReport{
					Subject:      "",
					ArtifactType: "application/vnd.cncf.notary.signature",
					VerifierReports: []vr.VerifierResult{
						{
							IsSuccess: true,
						},
					},
				},
				et.NestedVerifierReport{
					Subject:      "",
					ArtifactType: "application/spdx+json",
					VerifierReports: []vr.VerifierResult{
						{
							IsSuccess: true,
						},
					},
				},
			},
			output: true,
		},
	}

	ctx := context.Background()

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			config := pc.PoliciesConfig{
				Version:      "1.0.0",
				PolicyPlugin: testcase.configPolicyConfig,
			}

			policyEnforcer, err := pf.CreatePolicyProviderFromConfig(config)
			if err != nil {
				t.Fatalf("PolicyEnforcer should create from PoliciesConfig")
			}

			overallVerifyResult := policyEnforcer.OverallVerifyResult(ctx, testcase.verifierReports)
			if overallVerifyResult != testcase.output {
				t.Fatalf("Expected %v from OverallVerifyResult but got %v", testcase.output, overallVerifyResult)
			}
		})
	}
}

func TestGetPolicyType(t *testing.T) {
	enforcer := PolicyEnforcer{}
	if policyType := enforcer.GetPolicyType(context.Background()); policyType != "configpolicy" {
		t.Fatalf("expected policy type: configpolicy, got %v", policyType)
	}
}
