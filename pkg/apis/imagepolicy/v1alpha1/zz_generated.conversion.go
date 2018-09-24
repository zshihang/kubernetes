// +build !ignore_autogenerated

/*
Copyright The Kubernetes Authors.

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

// Code generated by conversion-gen. DO NOT EDIT.

package v1alpha1

import (
	unsafe "unsafe"

	v1alpha1 "k8s.io/api/imagepolicy/v1alpha1"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
	imagepolicy "k8s.io/kubernetes/pkg/apis/imagepolicy"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(scheme *runtime.Scheme) error {
	return scheme.AddGeneratedConversionFuncs(
		Convert_v1alpha1_ImageReview_To_imagepolicy_ImageReview,
		Convert_imagepolicy_ImageReview_To_v1alpha1_ImageReview,
		Convert_v1alpha1_ImageReviewContainerSpec_To_imagepolicy_ImageReviewContainerSpec,
		Convert_imagepolicy_ImageReviewContainerSpec_To_v1alpha1_ImageReviewContainerSpec,
		Convert_v1alpha1_ImageReviewSpec_To_imagepolicy_ImageReviewSpec,
		Convert_imagepolicy_ImageReviewSpec_To_v1alpha1_ImageReviewSpec,
		Convert_v1alpha1_ImageReviewStatus_To_imagepolicy_ImageReviewStatus,
		Convert_imagepolicy_ImageReviewStatus_To_v1alpha1_ImageReviewStatus,
	)
}

func autoConvert_v1alpha1_ImageReview_To_imagepolicy_ImageReview(in *v1alpha1.ImageReview, out *imagepolicy.ImageReview, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1alpha1_ImageReviewSpec_To_imagepolicy_ImageReviewSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	if err := Convert_v1alpha1_ImageReviewStatus_To_imagepolicy_ImageReviewStatus(&in.Status, &out.Status, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1alpha1_ImageReview_To_imagepolicy_ImageReview is an autogenerated conversion function.
func Convert_v1alpha1_ImageReview_To_imagepolicy_ImageReview(in *v1alpha1.ImageReview, out *imagepolicy.ImageReview, s conversion.Scope) error {
	return autoConvert_v1alpha1_ImageReview_To_imagepolicy_ImageReview(in, out, s)
}

func autoConvert_imagepolicy_ImageReview_To_v1alpha1_ImageReview(in *imagepolicy.ImageReview, out *v1alpha1.ImageReview, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_imagepolicy_ImageReviewSpec_To_v1alpha1_ImageReviewSpec(&in.Spec, &out.Spec, s); err != nil {
		return err
	}
	if err := Convert_imagepolicy_ImageReviewStatus_To_v1alpha1_ImageReviewStatus(&in.Status, &out.Status, s); err != nil {
		return err
	}
	return nil
}

// Convert_imagepolicy_ImageReview_To_v1alpha1_ImageReview is an autogenerated conversion function.
func Convert_imagepolicy_ImageReview_To_v1alpha1_ImageReview(in *imagepolicy.ImageReview, out *v1alpha1.ImageReview, s conversion.Scope) error {
	return autoConvert_imagepolicy_ImageReview_To_v1alpha1_ImageReview(in, out, s)
}

func autoConvert_v1alpha1_ImageReviewContainerSpec_To_imagepolicy_ImageReviewContainerSpec(in *v1alpha1.ImageReviewContainerSpec, out *imagepolicy.ImageReviewContainerSpec, s conversion.Scope) error {
	out.Image = in.Image
	return nil
}

// Convert_v1alpha1_ImageReviewContainerSpec_To_imagepolicy_ImageReviewContainerSpec is an autogenerated conversion function.
func Convert_v1alpha1_ImageReviewContainerSpec_To_imagepolicy_ImageReviewContainerSpec(in *v1alpha1.ImageReviewContainerSpec, out *imagepolicy.ImageReviewContainerSpec, s conversion.Scope) error {
	return autoConvert_v1alpha1_ImageReviewContainerSpec_To_imagepolicy_ImageReviewContainerSpec(in, out, s)
}

func autoConvert_imagepolicy_ImageReviewContainerSpec_To_v1alpha1_ImageReviewContainerSpec(in *imagepolicy.ImageReviewContainerSpec, out *v1alpha1.ImageReviewContainerSpec, s conversion.Scope) error {
	out.Image = in.Image
	return nil
}

// Convert_imagepolicy_ImageReviewContainerSpec_To_v1alpha1_ImageReviewContainerSpec is an autogenerated conversion function.
func Convert_imagepolicy_ImageReviewContainerSpec_To_v1alpha1_ImageReviewContainerSpec(in *imagepolicy.ImageReviewContainerSpec, out *v1alpha1.ImageReviewContainerSpec, s conversion.Scope) error {
	return autoConvert_imagepolicy_ImageReviewContainerSpec_To_v1alpha1_ImageReviewContainerSpec(in, out, s)
}

func autoConvert_v1alpha1_ImageReviewSpec_To_imagepolicy_ImageReviewSpec(in *v1alpha1.ImageReviewSpec, out *imagepolicy.ImageReviewSpec, s conversion.Scope) error {
	out.Containers = *(*[]imagepolicy.ImageReviewContainerSpec)(unsafe.Pointer(&in.Containers))
	out.Annotations = *(*map[string]string)(unsafe.Pointer(&in.Annotations))
	out.Namespace = in.Namespace
	return nil
}

// Convert_v1alpha1_ImageReviewSpec_To_imagepolicy_ImageReviewSpec is an autogenerated conversion function.
func Convert_v1alpha1_ImageReviewSpec_To_imagepolicy_ImageReviewSpec(in *v1alpha1.ImageReviewSpec, out *imagepolicy.ImageReviewSpec, s conversion.Scope) error {
	return autoConvert_v1alpha1_ImageReviewSpec_To_imagepolicy_ImageReviewSpec(in, out, s)
}

func autoConvert_imagepolicy_ImageReviewSpec_To_v1alpha1_ImageReviewSpec(in *imagepolicy.ImageReviewSpec, out *v1alpha1.ImageReviewSpec, s conversion.Scope) error {
	out.Containers = *(*[]v1alpha1.ImageReviewContainerSpec)(unsafe.Pointer(&in.Containers))
	out.Annotations = *(*map[string]string)(unsafe.Pointer(&in.Annotations))
	out.Namespace = in.Namespace
	return nil
}

// Convert_imagepolicy_ImageReviewSpec_To_v1alpha1_ImageReviewSpec is an autogenerated conversion function.
func Convert_imagepolicy_ImageReviewSpec_To_v1alpha1_ImageReviewSpec(in *imagepolicy.ImageReviewSpec, out *v1alpha1.ImageReviewSpec, s conversion.Scope) error {
	return autoConvert_imagepolicy_ImageReviewSpec_To_v1alpha1_ImageReviewSpec(in, out, s)
}

func autoConvert_v1alpha1_ImageReviewStatus_To_imagepolicy_ImageReviewStatus(in *v1alpha1.ImageReviewStatus, out *imagepolicy.ImageReviewStatus, s conversion.Scope) error {
	out.Allowed = in.Allowed
	out.Reason = in.Reason
	out.AuditAnnotations = *(*map[string]string)(unsafe.Pointer(&in.AuditAnnotations))
	return nil
}

// Convert_v1alpha1_ImageReviewStatus_To_imagepolicy_ImageReviewStatus is an autogenerated conversion function.
func Convert_v1alpha1_ImageReviewStatus_To_imagepolicy_ImageReviewStatus(in *v1alpha1.ImageReviewStatus, out *imagepolicy.ImageReviewStatus, s conversion.Scope) error {
	return autoConvert_v1alpha1_ImageReviewStatus_To_imagepolicy_ImageReviewStatus(in, out, s)
}

func autoConvert_imagepolicy_ImageReviewStatus_To_v1alpha1_ImageReviewStatus(in *imagepolicy.ImageReviewStatus, out *v1alpha1.ImageReviewStatus, s conversion.Scope) error {
	out.Allowed = in.Allowed
	out.Reason = in.Reason
	out.AuditAnnotations = *(*map[string]string)(unsafe.Pointer(&in.AuditAnnotations))
	return nil
}

// Convert_imagepolicy_ImageReviewStatus_To_v1alpha1_ImageReviewStatus is an autogenerated conversion function.
func Convert_imagepolicy_ImageReviewStatus_To_v1alpha1_ImageReviewStatus(in *imagepolicy.ImageReviewStatus, out *v1alpha1.ImageReviewStatus, s conversion.Scope) error {
	return autoConvert_imagepolicy_ImageReviewStatus_To_v1alpha1_ImageReviewStatus(in, out, s)
}
