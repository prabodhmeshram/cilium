// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nat

import (
	"bytes"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/ctmap"
)

type NatKey interface {
	bpf.MapKey

	// ToNetwork converts fields to network byte order.
	ToNetwork() NatKey

	// ToHost converts fields to host byte order.
	ToHost() NatKey

	// Dump contents of key to buffer. Returns true if successful.
	Dump(buffer *bytes.Buffer, reverse bool) bool

	// GetFlags flags containing the direction of the CtKey.
	GetFlags() uint8
}

// NatKey4 is needed to provide NatEntry type to Lookup values
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type NatKey4 struct {
	ctmap.CtKey4Global
}

// NewValue creates a new bpf.MapValue.
func (k *NatKey4) NewValue() bpf.MapValue { return &NatEntry4{} }

// ToNetwork converts ports to network byte order.
//
// This is necessary to prevent callers from implicitly converting
// the NatKey4 type here into a local key type in the nested
// CtKey4Global field.
func (k *NatKey4) ToNetwork() NatKey {
	return &NatKey4{
		CtKey4Global: *k.CtKey4Global.ToNetwork().(*ctmap.CtKey4Global),
	}
}

// ToHost converts ports to host byte order.
//
// This is necessary to prevent callers from implicitly converting
// the NatKey4 type here into a local key type in the nested
// CtKey4Global field.
func (k *NatKey4) ToHost() NatKey {
	return &NatKey4{
		CtKey4Global: *k.CtKey4Global.ToHost().(*ctmap.CtKey4Global),
	}
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *NatKey4) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// NatKey6 is needed to provide NatEntry type to Lookup values
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type NatKey6 struct {
	ctmap.CtKey6Global
}

// NewValue creates a new bpf.MapValue.
func (k *NatKey6) NewValue() bpf.MapValue { return &NatEntry4{} }

// ToNetwork converts ports to network byte order.
//
// This is necessary to prevent callers from implicitly converting
// the NatKey6 type here into a local key type in the nested
// CtKey6Global field.
func (k *NatKey6) ToNetwork() NatKey {
	return &NatKey6{
		CtKey6Global: *k.CtKey6Global.ToNetwork().(*ctmap.CtKey6Global),
	}
}

// ToHost converts ports to host byte order.
//
// This is necessary to prevent callers from implicitly converting
// the NatKey6 type here into a local key type in the nested
// CtKey6Global field.
func (k *NatKey6) ToHost() NatKey {
	return &NatKey6{
		CtKey6Global: *k.CtKey6Global.ToHost().(*ctmap.CtKey6Global),
	}
}

// GetKeyPtr returns the unsafe.Pointer for k.
func (k *NatKey6) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }
