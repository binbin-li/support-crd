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

import (
	v1beta1 "github.com/deislabs/ratify/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/conversion"
)

// ConvertFrom converts from the Hub version(v1beta1) to this version.
// nolint:revive
func (dst *Store) ConvertFrom(srcRaw conversion.Hub) error {
	src := srcRaw.(*v1beta1.Store)

	return Convert_v1beta1_Store_To_v1alpha1_Store(src, dst, nil)
}

// ConvertTo converts this version to the Hub version(v1beta1).
// nolint:revive
func (src *Store) ConvertTo(dstRaw conversion.Hub) error {
	dst := dstRaw.(*v1beta1.Store)

	return Convert_v1alpha1_Store_To_v1beta1_Store(src, dst, nil)
}