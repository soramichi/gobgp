// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"github.com/jessevdk/go-flags"
	"github.com/osrg/gobgp/api"
	"golang.org/x/net/context"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
)

type GlobalCommand struct{}

func (x *GlobalCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_GLOBAL)
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "global"
	parser.AddCommand(CMD_RIB, "subcommand for rib of global", "", &GlobalRibCommand{})
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}
	return nil
}

type GlobalRibCommand struct{}

func showGlobalRib() error {
	rt, err := checkAddressFamily(net.IP{})
	if err != nil {
		return err
	}
	arg := &api.Arguments{
		Resource: api.Resource_GLOBAL,
		Af:       rt,
	}

	stream, e := client.GetRib(context.Background(), arg)
	if e != nil {
		return e
	}
	ds := []*api.Destination{}
	for {
		d, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		ds = append(ds, d)
	}

	if globalOpts.Json {
		j, _ := json.Marshal(ds)
		fmt.Println(string(j))
		return nil
	}

	ps := paths{}
	for _, d := range ds {
		for idx, p := range d.Paths {
			if idx == int(d.BestPathIdx) {
				p.Best = true
			}
			ps = append(ps, p)
		}
	}

	sort.Sort(ps)

	showRoute(ps, true, true)
	return nil
}
func (x *GlobalRibCommand) Execute(args []string) error {

	eArgs := extractArgs(CMD_RIB)
	parser := flags.NewParser(&subOpts, flags.Default)
	if len(eArgs) == 0 || (len(eArgs) < 3 && eArgs[0] == "-a") {
		if _, err := parser.ParseArgs(eArgs); err != nil {
			os.Exit(1)
		}
		if err := requestGrpc(CMD_GLOBAL+"_"+CMD_RIB, eArgs, nil); err != nil {
			return err
		}
	} else {
		parser.Usage = "global rib [OPTIONS]\n  gobgp global rib"
		parser.AddCommand(CMD_ADD, "subcommand to add route to global rib", "", &GlobalRibAddCommand{})
		parser.AddCommand(CMD_DEL, "subcommand to delete route from global rib", "", &GlobalRibDelCommand{})
		if _, err := parser.ParseArgs(eArgs); err != nil {
			os.Exit(1)
		}
	}
	return nil
}

type GlobalRibAddCommand struct{}

func modPath(modtype string, eArgs []string) error {
	rf, err := checkAddressFamily(net.IP{})
	if err != nil {
		return err
	}

	path := &api.Path{}
	var prefix, macAddr, ipAddr string
	switch rf {
	case api.AF_IPV4_UC, api.AF_IPV6_UC:
		if len(eArgs) == 1 || len(eArgs) == 3 {
			prefix = eArgs[0]
		} else {
			return fmt.Errorf("usage: global rib %s <prefix> -a { ipv4 | ipv6 }", modtype)
		}
		path.Nlri = &api.Nlri{
			Af:     rf,
			Prefix: prefix,
		}
	case api.AF_EVPN:
		if len(eArgs) == 4 {
			macAddr = eArgs[0]
			ipAddr = eArgs[1]
		} else {
			return fmt.Errorf("usage: global rib %s <mac address> <ip address> -a evpn", modtype)
		}
		path.Nlri = &api.Nlri{
			Af: rf,
			EvpnNlri: &api.EVPNNlri{
				Type: api.EVPN_TYPE_ROUTE_TYPE_MAC_IP_ADVERTISEMENT,
				MacIpAdv: &api.EvpnMacIpAdvertisement{
					MacAddr: macAddr,
					IpAddr:  ipAddr,
				},
			},
		}
	case api.AF_ENCAP:
		if len(eArgs) < 3 {
			return fmt.Errorf("usage: global rib %s <end point ip address> [<vni>] -a encap", modtype)
		}
		prefix = eArgs[0]

		path.Nlri = &api.Nlri{
			Af:     rf,
			Prefix: prefix,
		}

		if len(eArgs) > 3 {
			vni, err := strconv.Atoi(eArgs[1])
			if err != nil {
				return fmt.Errorf("invalid vni: %s", eArgs[1])
			}
			subTlv := &api.TunnelEncapSubTLV{
				Type:  api.ENCAP_SUBTLV_TYPE_COLOR,
				Color: uint32(vni),
			}
			tlv := &api.TunnelEncapTLV{
				Type:   api.TUNNEL_TYPE_VXLAN,
				SubTlv: []*api.TunnelEncapSubTLV{subTlv},
			}
			attr := &api.PathAttr{
				Type:        api.BGP_ATTR_TYPE_TUNNEL_ENCAP,
				TunnelEncap: []*api.TunnelEncapTLV{tlv},
			}

			path.Attrs = append(path.Attrs, attr)
		}
	case api.AF_RTC:
		if !(len(eArgs) == 3 && eArgs[0] == "default") && len(eArgs) < 4 {
			return fmt.Errorf("usage: global rib add <asn> <local admin> -a rtc")
		}
		var asn, admin int

		if eArgs[0] != "default" {
			asn, err = strconv.Atoi(eArgs[0])
			if err != nil {
				return fmt.Errorf("invalid asn: %s", eArgs[0])
			}
			admin, err = strconv.Atoi(eArgs[1])
			if err != nil {
				return fmt.Errorf("invalid local admin: %s", eArgs[1])
			}
		}
		path.Nlri = &api.Nlri{
			Af: rf,
			RtNlri: &api.RTNlri{
				Target: &api.ExtendedCommunity{
					Type:       api.EXTENDED_COMMUNITIE_TYPE_TWO_OCTET_AS_SPECIFIC,
					Subtype:    api.EXTENDED_COMMUNITIE_SUBTYPE_ROUTE_TARGET,
					Asn:        uint32(asn),
					LocalAdmin: uint32(admin),
				},
			},
		}
	}
	switch modtype {
	case CMD_ADD:
		path.IsWithdraw = false
	case CMD_DEL:
		path.IsWithdraw = true
	}

	arg := &api.ModPathArguments{
		Resource: api.Resource_GLOBAL,
		Path:     path,
	}
	stream, err := client.ModPath(context.Background())
	if err != nil {
		return err
	}
	err = stream.Send(arg)
	if err != nil {
		return err
	}
	stream.CloseSend()

	res, e := stream.Recv()
	if e != nil {
		return e
	}
	if res.Code != api.Error_SUCCESS {
		return fmt.Errorf("error: code: %d, msg: %s", res.Code, res.Msg)
	}
	return nil
}

func (x *GlobalRibAddCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_ADD)
	parser := flags.NewParser(&subOpts, flags.Default)
	parser.Usage = "global rib add <prefix> -a { ipv4 | ipv6 }\n" +
		"    -> if -a option is ipv4 or ipv6\n" +
		"  gobgp global rib add <mac address> <ip address> -a evpn\n" +
		"    -> if -a option is evpn"
	parser.ParseArgs(eArgs)
	if len(eArgs) == 1 {
		if eArgs[0] == "-h" || eArgs[0] == "--help" {
			return nil
		}
	}
	if err := requestGrpc(CMD_GLOBAL+"_"+CMD_RIB+"_"+CMD_ADD, eArgs, nil); err != nil {
		return err
	}
	return nil
}

type GlobalRibDelCommand struct{}

func (x *GlobalRibDelCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_DEL)
	parser := flags.NewParser(&subOpts, flags.Default)
	parser.Usage = "global rib del <prefix> -a { ipv4 | ipv6 }\n" +
		"    -> if -a option is ipv4 or ipv6\n" +
		"  gobgp global rib del <mac address> <ip address> -a evpn\n" +
		"    -> if -a option is evpn"
	parser.ParseArgs(eArgs)
	if len(eArgs) == 1 {
		if eArgs[0] == "-h" || eArgs[0] == "--help" {
			return nil
		}
	}
	if err := requestGrpc(CMD_GLOBAL+"_"+CMD_RIB+"_"+CMD_DEL, eArgs, nil); err != nil {
		return err
	}
	return nil
}
