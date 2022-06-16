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


package v1alpha1

import metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// VerifierType +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type VerifierType struct {
	metaV1.TypeMeta   `json:",inline"`
	metaV1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VerifierTypeSpec   `json:"spec"`
	Status VerifierTypeStatus `json:"status"`
}

type VerifierTypeSpec struct {
	Type string               `json:"type"`
	Address string            `json:"address"`
	ArtifactType string       `json:"artifactTye"`
	Params map[string]string  `json:"params"`
}

type VerifierTypeStatus struct {
	State   string `json:"state,omitempty"`
	Message string `json:"message,omitempty"`
}

// VerifierTypeList +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type VerifierTypeList struct {
	metaV1.TypeMeta   `json:",inline"`
	metaV1.ObjectMeta `json:"metadata,omitempty"`

	Items []VerifierType `json:"items"`
}

// StoreType +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type StoreType struct {
	metaV1.TypeMeta   `json:",inline"`
	metaV1.ObjectMeta `json:"metadata,omitempty"`

	Spec   StoreTypeSpec   `json:"spec"`
	Status StoreTypeStatus `json:"status"`
}

type StoreTypeSpec struct {
	Type string `json:"type"`
	Address string `json:"address"`
	Auth map[string]string `json:"auth"`
}

type StoreTypeStatus struct {
	State   string `json:"state,omitempty"`
	Message string `json:"message,omitempty"`
}

// StoreTypeList +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type StoreTypeList struct {
	metaV1.TypeMeta   `json:",inline"`
	metaV1.ObjectMeta `json:"metadata,omitempty"`

	Items []StoreType `json:"items"`
}