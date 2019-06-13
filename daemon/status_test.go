// Copyright 2016-2019 Authors of Cilium
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

// +build !privileged_tests

package main

import (
	"reflect"
	"testing"

	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/go-openapi/runtime/middleware"
)

func Test_getNodes_Handle(t *testing.T) {
	type fields struct {
		d       *Daemon
		RWMutex lock.RWMutex
		clients map[int64]*clusterNodesClient
	}
	type args struct {
		params GetClusterNodesParams
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   middleware.Responder
	}{
		{},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &getNodes{
				d:       tt.fields.d,
				RWMutex: tt.fields.RWMutex,
				clients: tt.fields.clients,
			}
			if got := h.Handle(tt.args.params); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getNodes.Handle() = %v, want %v", got, tt.want)
			}
		})
	}
}
