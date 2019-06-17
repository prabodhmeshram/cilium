// Copyright 2017-2019 Authors of Cilium
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

package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/nat"
	"github.com/cilium/cilium/pkg/option"

	"github.com/spf13/cobra"
)

// bpfCtFlushCmd represents the bpf_ct_flush command
var bpfCtFlushCmd = &cobra.Command{
	Use:    "flush ( <endpoint identifier> | global )",
	Short:  "Flush all connection tracking entries",
	PreRun: requireEndpointIDorGlobal,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf ct flush")
		flushCt(args[0])
	},
}

func init() {
	bpfCtCmd.AddCommand(bpfCtFlushCmd)
}

type dummyEndpoint struct {
	ID int
}

func init() {
	natGlobalMaps := nat.GlobalMaps(true, true)
	global4Map := natGlobalMaps[0]
	global6Map := natGlobalMaps[1]

	// SNAT also only works if the CT map is global so all local maps will be nil
	ctmap.InitMapInfo(option.Config.CTMapEntriesGlobalTCP, option.Config.CTMapEntriesGlobalAny,
		map[ctmap.MapType]ctmap.NatMap{
			ctmap.MapTypeIPv4TCPLocal:  nil,
			ctmap.MapTypeIPv6TCPLocal:  nil,
			ctmap.MapTypeIPv4TCPGlobal: global4Map,
			ctmap.MapTypeIPv6TCPGlobal: global6Map,
			ctmap.MapTypeIPv4AnyLocal:  nil,
			ctmap.MapTypeIPv6AnyLocal:  nil,
			ctmap.MapTypeIPv4AnyGlobal: global4Map,
			ctmap.MapTypeIPv6AnyGlobal: global6Map,
		},
	)
}

func (d dummyEndpoint) GetID() uint64 {
	return uint64(d.ID)
}

func flushCt(eID string) {
	var maps []*ctmap.Map
	if eID == "global" {
		maps = ctmap.GlobalMaps(true, true)
	} else {
		id, _ := strconv.Atoi(eID)
		maps = ctmap.LocalMaps(&dummyEndpoint{ID: id}, true, true)
	}
	for _, m := range maps {
		path, err := m.Path()
		if err == nil {
			err = m.Open()
		}
		if err != nil {
			if err == os.ErrNotExist {
				Fatalf("Unable to open %s: %s: please try using \"cilium bpf ct flush global\"", path, err)
			} else {
				Fatalf("Unable to open %s: %s", path, err)
			}
			continue
		}
		defer m.Close()
		entries := m.Flush()
		fmt.Printf("Flushed %d entries from %s\n", entries, path)
	}
}
