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

package ctmap

import (
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"
)

// CtKey4 is needed to provide CtEntry type to Lookup values
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type CtKey4 struct {
	tuple.TupleKey4
}

// NewValue creates a new bpf.MapValue.
func (k *CtKey4) NewValue() bpf.MapValue { return &CtEntry{} }

// ToNetwork converts CtKey4 ports to network byte order.
func (k *CtKey4) ToNetwork() tuple.TupleKey {
	n := *k
	n.SourcePort = byteorder.HostToNetwork(n.SourcePort).(uint16)
	n.DestPort = byteorder.HostToNetwork(n.DestPort).(uint16)
	return &n
}

// CtKey4Global is needed to provide CtEntry type to Lookup values
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type CtKey4Global struct {
	tuple.TupleKey4Global
}

// NewValue creates a new bpf.MapValue.
func (k *CtKey4Global) NewValue() bpf.MapValue { return &CtEntry{} }

// ToNetwork converts CtKey4Global ports to network byte order.
func (k *CtKey4Global) ToNetwork() tuple.TupleKey {
	n := *k
	n.SourcePort = byteorder.HostToNetwork(n.SourcePort).(uint16)
	n.DestPort = byteorder.HostToNetwork(n.DestPort).(uint16)
	return &n
}

// CtKey6 is needed to provide CtEntry type to Lookup values
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type CtKey6 struct {
	tuple.TupleKey6
}

// NewValue creates a new bpf.MapValue.
func (k *CtKey6) NewValue() bpf.MapValue { return &CtEntry{} }

// ToNetwork converts CtKey6 ports to network byte order.
func (k *CtKey6) ToNetwork() tuple.TupleKey {
	n := *k
	n.SourcePort = byteorder.HostToNetwork(n.SourcePort).(uint16)
	n.DestPort = byteorder.HostToNetwork(n.DestPort).(uint16)
	return &n
}

// CtKey6Global is needed to provide CtEntry type to Lookup values
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type CtKey6Global struct {
	tuple.TupleKey6Global
}

// NewValue creates a new bpf.MapValue.
func (k *CtKey6Global) NewValue() bpf.MapValue { return &CtEntry{} }

// ToNetwork converts CtKey6Global ports to network byte order.
func (k *CtKey6Global) ToNetwork() tuple.TupleKey {
	n := *k
	n.SourcePort = byteorder.HostToNetwork(n.SourcePort).(uint16)
	n.DestPort = byteorder.HostToNetwork(n.DestPort).(uint16)
	return &n
}

func createTupleKey(isGlobal bool, remoteAddr, localAddr string, proto u8proto.U8proto, ingress bool) (bpf.MapKey, bool, error) {
	ip, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil, false, fmt.Errorf("invalid remote address '%s': %s", remoteAddr, err)
	}

	sIP := net.ParseIP(ip)
	if sIP == nil {
		return nil, false, fmt.Errorf("unable to parse IP %s", ip)
	}

	sport, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, false, fmt.Errorf("unable to parse port string: %s", err)
	}

	localIp, localPort, err := net.SplitHostPort(localAddr)
	if err != nil {
		return nil, false, fmt.Errorf("invalid local address '%s': %s", localAddr, err)
	}

	dIP := net.ParseIP(localIp)
	if dIP == nil {
		return nil, false, fmt.Errorf("unable to parse IP %s", localIp)
	}

	dport, err := strconv.ParseUint(localPort, 10, 16)
	if err != nil {
		return nil, false, fmt.Errorf("unable to parse port string: %s", err)
	}

	if sIP.To4() != nil {
		if isGlobal {
			key := &CtKey4Global{
				TupleKey4Global: tuple.TupleKey4Global{
					TupleKey4: tuple.TupleKey4{
						SourcePort: uint16(sport),
						DestPort:   uint16(dport),
						NextHeader: proto,
						Flags:      TUPLE_F_OUT,
					},
				},
			}
			// CTmap has the addresses in the reverse order w.r.t. the original direction
			copy(key.SourceAddr[:], dIP.To4())
			copy(key.DestAddr[:], sIP.To4())
			if ingress {
				key.Flags = TUPLE_F_IN
			}
			return key.ToNetwork(), true, nil
		}

		key := &CtKey4{
			TupleKey4: tuple.TupleKey4{
				SourcePort: uint16(sport),
				DestPort:   uint16(dport),
				NextHeader: proto,
				Flags:      TUPLE_F_OUT,
			},
		}
		// CTmap has the addresses in the reverse order w.r.t. the original direction
		copy(key.SourceAddr[:], dIP.To4())
		copy(key.DestAddr[:], sIP.To4())
		if ingress {
			key.Flags = TUPLE_F_IN
		}
		return key.ToNetwork(), true, nil
	}

	if isGlobal {
		key := &CtKey6Global{
			TupleKey6Global: tuple.TupleKey6Global{
				TupleKey6: tuple.TupleKey6{
					SourcePort: uint16(sport),
					DestPort:   uint16(dport),
					NextHeader: proto,
					Flags:      TUPLE_F_OUT,
				},
			},
		}
		// CTmap has the addresses in the reverse order w.r.t. the original direction
		copy(key.SourceAddr[:], dIP.To16())
		copy(key.DestAddr[:], sIP.To16())
		if ingress {
			key.Flags = TUPLE_F_IN
		}
		return key.ToNetwork(), false, nil
	}

	key := &CtKey6{
		TupleKey6: tuple.TupleKey6{
			SourcePort: uint16(sport),
			DestPort:   uint16(dport),
			NextHeader: proto,
			Flags:      TUPLE_F_OUT,
		},
	}
	// CTmap has the addresses in the reverse order w.r.t. the original direction
	copy(key.SourceAddr[:], dIP.To16())
	copy(key.DestAddr[:], sIP.To16())
	if ingress {
		key.Flags = TUPLE_F_IN
	}
	return key.ToNetwork(), false, nil
}

func getMapName(mapname string, ipv4 bool, proto u8proto.U8proto) string {
	if ipv4 {
		if proto == u8proto.TCP {
			mapname = MapNameTCP4 + mapname
		} else {
			mapname = MapNameAny4 + mapname
		}
	} else {
		if proto == u8proto.TCP {
			mapname = MapNameTCP6 + mapname
		} else {
			mapname = MapNameAny6 + mapname
		}
	}
	return mapname
}

// Lookup opens a conntrack map if necessary, and does a lookup on it with a key constructed from
// the parameters
// 'epname' is a 5-digit representation of the endpoint ID if local maps
// are to be used, or "global" if global maps should be used.
func Lookup(epname string, remoteAddr, localAddr string, proto u8proto.U8proto, ingress bool) (*CtEntry, error) {
	isGlobal := epname == "global"

	key, ipv4, err := createTupleKey(isGlobal, remoteAddr, localAddr, proto, ingress)
	if err != nil {
		return nil, err
	}

	mapname := getMapName(epname, ipv4, proto)

	m := bpf.GetMap(mapname)
	if m == nil {
		// Open the map and leave it open
		m, err = bpf.OpenMap(mapname)
		if err != nil {
			return nil, fmt.Errorf("Can not open CT map %s: %s", mapname, err)
		}
		if isGlobal {
			if ipv4 {
				m.MapKey = &CtKey4Global{}
			} else {
				m.MapKey = &CtKey6Global{}
			}
		} else {
			if ipv4 {
				m.MapKey = &CtKey4{}
			} else {
				m.MapKey = &CtKey6{}
			}
		}
		m.MapValue = &CtEntry{}
	}

	v, err := m.Lookup(key)
	if err != nil || v == nil {
		return nil, err
	}
	return v.(*CtEntry), err
}

func getMapWithName(epname string, ipv4 bool, proto u8proto.U8proto) *bpf.Map {
	return bpf.GetMap(getMapName(epname, ipv4, proto))
}

// CloseLocalMaps closes all local conntrack maps opened previously
// for lookup with the given 'mapname'.
func CloseLocalMaps(mapname string) {
	// only close local maps. Global map is kept open as long as cilium-agent is running.
	if mapname != "global" {
		// close IPv4 maps, if any
		if m := getMapWithName(mapname, true, u8proto.TCP); m != nil {
			m.Close()
		}
		if m := getMapWithName(mapname, true, u8proto.UDP); m != nil {
			m.Close()
		}

		// close IPv6 maps, if any
		if m := getMapWithName(mapname, false, u8proto.TCP); m != nil {
			m.Close()
		}
		if m := getMapWithName(mapname, false, u8proto.UDP); m != nil {
			m.Close()
		}
	}
}
