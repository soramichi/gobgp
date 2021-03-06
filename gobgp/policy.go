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
	"github.com/osrg/gobgp/policy"
	"golang.org/x/net/context"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

type PolicyCommand struct{}

func (x *PolicyCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_POLICY)
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy"
	parser.AddCommand(CMD_PREFIX, "subcommand for prefix of policy", "", &PolicyPrefixCommand{})
	parser.AddCommand(CMD_NEIGHBOR, "subcommand for neighbor of policy", "", &PolicyNeighborCommand{})
	parser.AddCommand(CMD_ROUTEPOLICY, "subcommand for routepolicy of policy", "", &PolicyRoutePolicyCommand{})
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}
	return nil
}

type PolicyPrefixCommand struct{}

func formatPolicyPrefix(prefixSetList []*api.PrefixSet) (string, string) {
	maxNameLen := len("Name")
	maxPrefixLen := len("Prefix")
	maxRangeLen := len("MaskRange")
	for _, ps := range prefixSetList {
		if len(ps.PrefixSetName) > maxNameLen {
			maxNameLen = len(ps.PrefixSetName)
		}
		for _, p := range ps.PrefixList {
			if len(p.Address)+len(fmt.Sprint(p.MaskLength))+1 > maxPrefixLen {
				maxPrefixLen = len(p.Address) + len(fmt.Sprint(p.MaskLength)) + 1
			}
			if len(p.MaskLengthRange) > maxRangeLen {
				maxRangeLen = len(p.MaskLengthRange)
			}
		}
	}
	formatPrefixSet := "%-" + fmt.Sprint(maxNameLen) + "s  %-" + fmt.Sprint(maxPrefixLen) + "s  %-" + fmt.Sprint(maxRangeLen) + "s\n"
	formatPrefixListOnly := "%-" + fmt.Sprint(maxPrefixLen) + "s  %-" + fmt.Sprint(maxRangeLen) + "s\n"
	return formatPrefixSet, formatPrefixListOnly
}

func showPolicyPrefixes() error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_PREFIX,
	}
	stream, e := client.GetPolicyPrefixes(context.Background(), arg)
	if e != nil {
		fmt.Println(e)
		return e
	}
	m := prefixes{}
	for {
		p, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		m = append(m, p)
	}

	if globalOpts.Json {
		j, _ := json.Marshal(m)
		fmt.Println(string(j))
		return nil
	}

	if globalOpts.Quiet {
		for _, p := range m {
			fmt.Println(p.PrefixSetName)
		}
		return nil
	}
	sort.Sort(m)

	format, _ := formatPolicyPrefix(m)
	fmt.Printf(format, "Name", "Prefix", "MaskRange")
	for _, ps := range m {
		for i, p := range ps.PrefixList {
			prefix := fmt.Sprintf("%s/%d", p.Address, p.MaskLength)
			if i == 0 {
				fmt.Printf(format, ps.PrefixSetName, prefix, p.MaskLengthRange)
			} else {
				fmt.Printf(format, "", prefix, p.MaskLengthRange)
			}
		}
	}
	return nil
}

func showPolicyPrefix(args []string) error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_PREFIX,
		Name:     args[0],
	}
	ps, e := client.GetPolicyPrefix(context.Background(), arg)
	if e != nil {
		return e
	}

	if globalOpts.Json {
		j, _ := json.Marshal(ps)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		for _, p := range ps.PrefixList {
			fmt.Printf("%s/%d %s\n", p.Address, p.MaskLength, p.MaskLengthRange)
		}
		return nil
	}
	format, _ := formatPolicyPrefix([]*api.PrefixSet{ps})
	fmt.Printf(format, "Name", "Prefix", "MaskRange")
	for i, p := range ps.PrefixList {
		prefix := fmt.Sprintf("%s/%d", p.Address, p.MaskLength)
		if i == 0 {
			fmt.Printf(format, ps.PrefixSetName, prefix, p.MaskLengthRange)
		} else {
			fmt.Printf(format, "", prefix, p.MaskLengthRange)
		}
	}
	return nil
}

func (x *PolicyPrefixCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_PREFIX)
	if len(eArgs) == 0 {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_PREFIX, eArgs, nil); err != nil {
			return err
		}
		return nil
	} else if len(eArgs) >= 1 && !(eArgs[0] == "-h" || eArgs[0] == "--help" || eArgs[0] == CMD_ADD || eArgs[0] == CMD_DEL) {
		if len(eArgs) != 1 {
			return fmt.Errorf("Argument can not be entered: %s", eArgs[1:])
		}
		if err := requestGrpc(CMD_POLICY+"_"+CMD_PREFIX, eArgs, nil); err != nil {
			return err
		}
		return nil
	}
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy prefix [<prefix set name>],\n  gobgp policy prefix"
	parser.AddCommand(CMD_ADD, "subcommand to add prefix condition to policy", "", &PolicyPrefixAddCommand{})
	parser.AddCommand(CMD_DEL, "subcommand to delete prefix condition from policy", "", &PolicyPrefixDelCommand{})
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}
	return nil
}

type PolicyPrefixAddCommand struct{}

func parsePrefixSet(eArgs []string) (*api.PrefixSet, error) {
	_, ipNet, e := net.ParseCIDR(eArgs[1])
	if e != nil {
		return nil, fmt.Errorf("invalid prefix: %s\nplease enter ipv4 or ipv6 format", eArgs[1])
	}
	mask, _ := ipNet.Mask.Size()
	prefix := &api.Prefix{
		Address:    ipNet.IP.String(),
		MaskLength: uint32(mask),
	}

	if len(eArgs) == 3 {
		maskRange := eArgs[2]
		idx := strings.Index(maskRange, "..")
		if idx == -1 {
			return nil, fmt.Errorf("invalid mask length range: %s", maskRange)
		}
		var min, max int
		var e error
		if idx != 0 {
			if min, e = strconv.Atoi(maskRange[:idx]); e != nil {
				return nil, fmt.Errorf("invalid mask length range: %s", maskRange)
			}
		}
		if idx != len(maskRange)-1 {
			if max, e = strconv.Atoi(maskRange[idx+2:]); e != nil {
				return nil, fmt.Errorf("invalid mask length range: %s", maskRange)
			}
		}
		if ipv4 := ipNet.IP.To4(); ipv4 != nil {
			if min < 0 || 32 < max {
				return nil, fmt.Errorf("ipv4 mask length range outside scope :%s", maskRange)
			}
		} else {
			if min < 0 || 128 < max {
				return nil, fmt.Errorf("ipv6 mask length range outside scope :%s", maskRange)
			}
		}
		if min >= max {
			return nil, fmt.Errorf("invalid mask length range: %s\nlarge value to the right from the left", maskRange)
		}
		prefix.MaskLengthRange = maskRange
	}
	prefixList := []*api.Prefix{prefix}
	prefixSet := &api.PrefixSet{
		PrefixSetName: eArgs[0],
		PrefixList:    prefixList,
	}
	return prefixSet, nil
}

func modPolicyPrefix(modtype string, eArgs []string) error {
	prefixSet := &api.PrefixSet{}
	var e error
	var operation api.Operation

	switch modtype {
	case CMD_ADD:
		if len(eArgs) < 2 {
			return fmt.Errorf("usage: policy prefix add <prefix set name> <prefix> [<mask length renge>]")
		}
		if prefixSet, e = parsePrefixSet(eArgs); e != nil {
			return e
		}
		operation = api.Operation_ADD
	case CMD_DEL:
		if len(eArgs) == 0 {
			operation = api.Operation_DEL_ALL
		} else if len(eArgs) == 1 {
			prefixSet = &api.PrefixSet{
				PrefixSetName: eArgs[0],
				PrefixList:    nil,
			}
			operation = api.Operation_DEL
		} else {
			if prefixSet, e = parsePrefixSet(eArgs); e != nil {
				return e
			}
			operation = api.Operation_DEL
		}
	}

	arg := &api.PolicyArguments{
		Resource:  api.Resource_POLICY_PREFIX,
		Operation: operation,
		PrefixSet: prefixSet,
	}
	stream, err := client.ModPolicyPrefix(context.Background())
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

func (x *PolicyPrefixAddCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_ADD)
	if len(eArgs) == 0 || len(eArgs) > 3 {
		return fmt.Errorf("usage: policy prefix add <prefix set name> <prefix> [<mask length renge> ]")
	} else {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_PREFIX+"_"+CMD_ADD, eArgs, nil); err != nil {
			return err
		}
	}
	return nil
}

type PolicyPrefixDelCommand struct{}

func (x *PolicyPrefixDelCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_DEL)
	if len(eArgs) > 3 {
		return fmt.Errorf("usage: policy prefix del <prefix set name> [<prefix> [<mask length range>]] ")
	} else if len(eArgs) > 0 && !(eArgs[0] == "-h" || eArgs[0] == "--help" || eArgs[0] == "all") {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_PREFIX+"_"+CMD_DEL, eArgs, nil); err != nil {
			return err
		}
		return nil
	}
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy prefix del <prefix set name> [<prefix> [<mask length range>]],\n  gobgp policy prefix del"
	parser.AddCommand(CMD_ALL, "subcommand to delete all prefix condition from policy", "", &PolicyPrefixDelAllCommand{})
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}
	return nil
}

type PolicyPrefixDelAllCommand struct{}

func (x *PolicyPrefixDelAllCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_ALL)
	if len(eArgs) > 0 {
		return fmt.Errorf("Argument can not be entered: %s", eArgs)
	}
	if err := requestGrpc(CMD_POLICY+"_"+CMD_PREFIX+"_"+CMD_DEL, eArgs, nil); err != nil {
		return err
	}
	return nil
}

type PolicyNeighborCommand struct{}

func formatPolicyNeighbor(neighborSetList []*api.NeighborSet) string {
	maxNameLen := len("Name")
	maxAddressLen := len("Address")
	for _, ns := range neighborSetList {
		if len(ns.NeighborSetName) > maxNameLen {
			maxNameLen = len(ns.NeighborSetName)
		}
		for _, n := range ns.NeighborList {
			if len(n.Address) > maxAddressLen {
				maxAddressLen = len(n.Address)
			}
		}
	}
	format := "%-" + fmt.Sprint(maxNameLen) + "s  %-" + fmt.Sprint(maxAddressLen) + "s\n"
	return format
}

func showPolicyNeighbors() error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_NEIGHBOR,
	}
	stream, e := client.GetPolicyNeighbors(context.Background(), arg)
	if e != nil {
		fmt.Println(e)
		return e
	}
	m := neighbors{}
	for {
		n, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		m = append(m, n)
	}

	if globalOpts.Json {
		j, _ := json.Marshal(m)
		fmt.Println(string(j))
		return nil
	}

	if globalOpts.Quiet {
		for _, n := range m {
			fmt.Println(n.NeighborSetName)
		}
		return nil
	}
	sort.Sort(m)

	format := formatPolicyNeighbor(m)
	fmt.Printf(format, "Name", "Address")
	for _, ns := range m {
		for i, n := range ns.NeighborList {
			if i == 0 {
				fmt.Printf(format, ns.NeighborSetName, n.Address)
			} else {
				fmt.Printf(format, "", n.Address)
			}
		}
	}
	return nil
}

func showPolicyNeighbor(args []string) error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_NEIGHBOR,
		Name:     args[0],
	}
	ns, e := client.GetPolicyNeighbor(context.Background(), arg)
	if e != nil {
		return e
	}

	if globalOpts.Json {
		j, _ := json.Marshal(ns)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		for _, n := range ns.NeighborList {
			fmt.Println(n.Address)
		}
		return nil
	}
	format := formatPolicyNeighbor([]*api.NeighborSet{ns})
	fmt.Printf(format, "Name", "Address")
	for i, n := range ns.NeighborList {
		if i == 0 {
			fmt.Printf(format, ns.NeighborSetName, n.Address)
		} else {
			fmt.Printf(format, "", n.Address)

		}
	}
	return nil
}

func (x *PolicyNeighborCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_NEIGHBOR)
	if len(eArgs) == 0 {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_NEIGHBOR, eArgs, nil); err != nil {
			return err
		}
		return nil
	} else if len(eArgs) >= 1 && !(eArgs[0] == "-h" || eArgs[0] == "--help" || eArgs[0] == CMD_ADD || eArgs[0] == CMD_DEL) {
		if len(eArgs) != 1 {
			return fmt.Errorf("Argument can not be entered: %s", eArgs[1:])
		}
		if err := requestGrpc(CMD_POLICY+"_"+CMD_NEIGHBOR, eArgs, nil); err != nil {
			return err
		}
		return nil
	}
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy neighbor [<neighbor set name>],\n  gobgp policy neighbor"
	parser.AddCommand(CMD_ADD, "subcommand to add neighbor condition to policy", "", &PolicyNeighborAddCommand{})
	parser.AddCommand(CMD_DEL, "subcommand to delete neighbor condition from policy", "", &PolicyNeighborDelCommand{})
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}
	return nil
}

type PolicyNeighborAddCommand struct{}

func parseNeighborSet(eArgs []string) (*api.NeighborSet, error) {
	address := net.ParseIP(eArgs[1])
	if address.To4() == nil {
		if address.To16() == nil {
			return nil, fmt.Errorf("invalid address: %s\nplease enter ipv4 or ipv6 format", eArgs[1])
		}
	}

	neighbor := &api.Neighbor{
		Address: address.String(),
	}
	neighborList := []*api.Neighbor{neighbor}
	neighborSet := &api.NeighborSet{
		NeighborSetName: eArgs[0],
		NeighborList:    neighborList,
	}
	return neighborSet, nil
}

func modPolicyNeighbor(modtype string, eArgs []string) error {
	neighborSet := &api.NeighborSet{}
	var e error
	var operation api.Operation

	switch modtype {
	case CMD_ADD:
		if len(eArgs) < 2 {
			return fmt.Errorf("usage: policy neighbor add <neighbor set name> <address>")
		}
		if neighborSet, e = parseNeighborSet(eArgs); e != nil {
			return e
		}
		operation = api.Operation_ADD
	case CMD_DEL:
		if len(eArgs) == 0 {
			operation = api.Operation_DEL_ALL
		} else if len(eArgs) == 1 {
			neighborSet = &api.NeighborSet{
				NeighborSetName: eArgs[0],
				NeighborList:    nil,
			}
			operation = api.Operation_DEL
		} else {
			if neighborSet, e = parseNeighborSet(eArgs); e != nil {
				return e
			}
			operation = api.Operation_DEL
		}
	}

	arg := &api.PolicyArguments{
		Resource:    api.Resource_POLICY_NEIGHBOR,
		Operation:   operation,
		NeighborSet: neighborSet,
	}
	stream, err := client.ModPolicyNeighbor(context.Background())
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

func (x *PolicyNeighborAddCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_ADD)
	if len(eArgs) == 0 || len(eArgs) > 2 {
		return fmt.Errorf("usage: policy neighbor add <neighbor set name> <address>")
	} else {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_NEIGHBOR+"_"+CMD_ADD, eArgs, nil); err != nil {
			return err
		}
	}
	return nil
}

type PolicyNeighborDelCommand struct{}

func (x *PolicyNeighborDelCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_DEL)
	if len(eArgs) > 3 {
		return fmt.Errorf("usage: policy neighbor del [<neighbor set name> [<address>]]")
	} else if len(eArgs) > 0 && !(eArgs[0] == "-h" || eArgs[0] == "--help" || eArgs[0] == "all") {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_NEIGHBOR+"_"+CMD_DEL, eArgs, nil); err != nil {
			return err
		}
		return nil
	}
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy neighbor del [<neighbor set name> [<address>]],\n  gobgp policy neighbor del"
	parser.AddCommand(CMD_ALL, "subcommand to delete all neighbor condition from policy", "", &PolicyNeighborDelAllCommand{})
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}
	return nil
}

type PolicyNeighborDelAllCommand struct{}

func (x *PolicyNeighborDelAllCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_ALL)
	if len(eArgs) > 0 {
		return fmt.Errorf("Argument can not be entered: %s", eArgs)
	}
	if err := requestGrpc(CMD_POLICY+"_"+CMD_NEIGHBOR+"_"+CMD_DEL, eArgs, nil); err != nil {
		return err
	}
	return nil
}

type PolicyRoutePolicyCommand struct{}

func showPolicyStatement(head string, pd *api.PolicyDefinition) {
	for _, st := range pd.StatementList {
		fmt.Printf("%s  StatementName %s:\n", head, st.StatementNeme)
		fmt.Printf("%s    Conditions:\n", head)
		prefixSet := st.Conditions.MatchPrefixSet
		fmt.Printf("%s      PrefixSet:    %s  ", head, prefixSet.PrefixSetName)
		if len(prefixSet.PrefixList) != 0 {
			nameFormat := "%-" + fmt.Sprint(len(prefixSet.PrefixSetName)+2) + "s"
			_, format := formatPolicyPrefix([]*api.PrefixSet{st.Conditions.MatchPrefixSet})
			for i, prefix := range prefixSet.PrefixList {
				p := fmt.Sprintf("%s/%d", prefix.Address, prefix.MaskLength)
				if i != 0 {
					fmt.Printf("%s                    ", head)
					fmt.Printf(nameFormat, "")
				}
				fmt.Printf(format, p, prefix.MaskLengthRange)
			}
		} else {
			fmt.Print("\n")
		}
		neighborSet := st.Conditions.MatchNeighborSet
		fmt.Printf("%s      NeighborSet:  %s  ", head, neighborSet.NeighborSetName)
		if len(neighborSet.NeighborList) != 0 {
			nameFormat := "%-" + fmt.Sprint(len(neighborSet.NeighborSetName)+2) + "s"
			for i, neighbor := range neighborSet.NeighborList {
				if i != 0 {
					fmt.Printf("%s                    ", head)
					fmt.Printf(nameFormat, "")
				}
				fmt.Println(neighbor.Address)
			}
		} else {
			fmt.Print("\n")
		}
		asPathLentgh := st.Conditions.MatchAsPathLength
		fmt.Printf("%s      AsPathLength: %s   %s\n", head, asPathLentgh.Operator, asPathLentgh.Value)
		fmt.Printf("%s      MatchOption:  %s\n", head, st.Conditions.MatchSetOptions)
		fmt.Printf("%s    Actions:\n", head)
		fmt.Printf("%s      %s\n", head, st.Actions.RouteAction)
	}

}

func showPolicyRoutePolicies() error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_ROUTEPOLICY,
	}
	stream, e := client.GetPolicyRoutePolicies(context.Background(), arg)
	if e != nil {
		fmt.Println(e)
		return e
	}
	m := policyDefinitions{}
	for {
		n, e := stream.Recv()
		if e == io.EOF {
			break
		} else if e != nil {
			return e
		}
		m = append(m, n)
	}

	if globalOpts.Json {
		j, _ := json.Marshal(m)
		fmt.Println(string(j))
		return nil
	}
	if globalOpts.Quiet {
		for _, p := range m {
			fmt.Println(p.PolicyDefinitionName)
		}
		return nil
	}
	sort.Sort(m)

	for _, pd := range m {
		fmt.Printf("PolicyName %s:\n", pd.PolicyDefinitionName)
		showPolicyStatement("", pd)
	}
	return nil
}

func showPolicyRoutePolicy(args []string) error {
	arg := &api.PolicyArguments{
		Resource: api.Resource_POLICY_ROUTEPOLICY,
		Name:     args[0],
	}
	pd, e := client.GetPolicyRoutePolicy(context.Background(), arg)
	if e != nil {
		return e
	}

	if globalOpts.Json {
		j, _ := json.Marshal(pd)
		fmt.Println(string(j))
		return nil
	}

	if globalOpts.Quiet {
		for _, st := range pd.StatementList {
			fmt.Println(st.StatementNeme)
		}
		return nil
	}

	fmt.Printf("PolicyName %s:\n", pd.PolicyDefinitionName)
	showPolicyStatement("", pd)
	return nil
}

func (x *PolicyRoutePolicyCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_ROUTEPOLICY)
	if len(eArgs) == 0 {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_ROUTEPOLICY, eArgs, nil); err != nil {
			return err
		}
		return nil
	} else if len(eArgs) >= 1 && !(eArgs[0] == "-h" || eArgs[0] == "--help" || eArgs[0] == CMD_ADD || eArgs[0] == CMD_DEL) {
		if len(eArgs) != 1 {
			return fmt.Errorf("Argument can not be entered: %s", eArgs[1:])
		}
		if err := requestGrpc(CMD_POLICY+"_"+CMD_ROUTEPOLICY, eArgs, nil); err != nil {
			return err
		}
		return nil
	}
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy routepolicy [<policy name>],\n  gobgp policy routepolicy"
	parser.AddCommand(CMD_ADD, "subcommand to add routing policy", "", &PolicyRoutePolicyAddCommand{})
	parser.AddCommand(CMD_DEL, "subcommand to delete routing policy", "", &PolicyRoutePolicyDelCommand{})
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}
	return nil
}

type PolicyRoutePolicyAddCommand struct{}

func parseConditions() (*api.Conditions, error) {
	conditions := &api.Conditions{}
	if conditionOpts.Prefix != "" {
		conditions.MatchPrefixSet = &api.PrefixSet{
			PrefixSetName: conditionOpts.Prefix,
		}
	}
	if conditionOpts.Neighbor != "" {
		conditions.MatchNeighborSet = &api.NeighborSet{
			NeighborSetName: conditionOpts.Neighbor,
		}
	}
	if conditionOpts.AsPathLength != "" {
		asPathLen := conditionOpts.AsPathLength
		idx := strings.Index(asPathLen, ",")
		if idx == -1 {
			return nil, fmt.Errorf("invalid as path length: %s\nPlease enter the <value>,<operator>", asPathLen)
		}
		operator := asPathLen[:idx]
		value := asPathLen[idx+1:]
		if _, err := strconv.ParseUint(value, 10, 32); err != nil {
			return nil, fmt.Errorf("invalid as path length: %s\nPlease enter a numeric", value)
		}
		conditions.MatchAsPathLength = &api.AsPathLength{
			Value:    value,
			Operator: operator,
		}
	}
	if conditionOpts.Option != "" {
		optionUpper := strings.ToUpper(conditionOpts.Option)
		var option string
		switch optionUpper {
		case policy.OPTIONS_ANY, policy.OPTIONS_ALL, policy.OPTIONS_INVERT:
			option = optionUpper
		default:
			return nil, fmt.Errorf("invalid condition option: %s\nPlease enter the any or all or invert",
				conditionOpts.Option)
		}
		conditions.MatchSetOptions = option
	}
	return conditions, nil
}

func parseActions() (*api.Actions, error) {
	actions := &api.Actions{}
	if actionOpts.RouteAction != "" {
		routeAction, e := parseRouteAction(actionOpts.RouteAction)
		if e != nil {
			return nil, e
		}
		actions.RouteAction = routeAction
	}
	return actions, nil
}

func modPolicyRoutePolicy(modtype string, stmtType string, eArgs []string, request interface{}) error {
	var e error
	var operation api.Operation
	pd := &api.PolicyDefinition{}
	switch modtype {
	case CMD_ADD:
		stmt := &api.Statement{}
		switch stmtType {
		case CMD_CONDITIONS:
			conditions, err := parseConditions()
			if err != nil {
				return err
			}
			stmt.StatementNeme = request.(*PolicyRoutePolicyAddConditionsCommand).statementName
			stmt.Conditions = conditions
			pd.PolicyDefinitionName = request.(*PolicyRoutePolicyAddConditionsCommand).policyName
		case CMD_ACTIONS:
			actions, err := parseActions()
			if err != nil {
				return err
			}
			stmt.StatementNeme = request.(*PolicyRoutePolicyAddActionsCommand).statementName
			stmt.Actions = actions
			pd.PolicyDefinitionName = request.(*PolicyRoutePolicyAddActionsCommand).policyName
		}
		pd.StatementList = []*api.Statement{stmt}
		operation = api.Operation_ADD

	case CMD_DEL:
		if len(eArgs) == 0 {
			operation = api.Operation_DEL_ALL
		} else if len(eArgs) == 1 {
			pd.PolicyDefinitionName = eArgs[0]
			operation = api.Operation_DEL
		} else if len(eArgs) == 2 {
			stmt := &api.Statement{
				StatementNeme: eArgs[1],
			}
			pd.PolicyDefinitionName = eArgs[0]
			pd.StatementList = []*api.Statement{stmt}
			operation = api.Operation_DEL
		}
	}
	arg := &api.PolicyArguments{
		Resource:         api.Resource_POLICY_ROUTEPOLICY,
		Operation:        operation,
		PolicyDifinition: pd,
	}
	stream, err := client.ModPolicyNeighbor(context.Background())
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

func (x *PolicyRoutePolicyAddCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_ADD)
	parser := flags.NewParser(nil, flags.Default)
	if len(eArgs) < 2 {
		return fmt.Errorf("usage: policy routepolicy add <routing policy name> <statement name>")
	}
	parser.Usage = "policy routepolicy add <routing policy name> <statement name>"
	parser.AddCommand(CMD_CONDITIONS, "subcommand for routing policy conditions", "", NewPolicyRoutePolicyAddConditionsCommand(eArgs[0], eArgs[1]))
	parser.AddCommand(CMD_ACTIONS, "subcommand for routing policy actions", "", NewPolicyRoutePolicyAddActionsCommand(eArgs[0], eArgs[1]))
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}
	return nil
}

type PolicyRoutePolicyAddConditionsCommand struct {
	policyName    string
	statementName string
}

func NewPolicyRoutePolicyAddConditionsCommand(pName string, sName string) *PolicyRoutePolicyAddConditionsCommand {
	return &PolicyRoutePolicyAddConditionsCommand{
		policyName:    pName,
		statementName: sName,
	}
}

func (x *PolicyRoutePolicyAddConditionsCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_CONDITIONS)
	parser := flags.NewParser(&conditionOpts, flags.Default)
	parser.Usage = "policy routepolicy add <routing policy name> <statement name> conditions [OPTIONS]"
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}
	if len(eArgs) == 0 {
		return fmt.Errorf("usage: policy routepolicy add <routing policy name> <statement name> conditions [OPTIONS]")
	} else if !(eArgs[0] == "-h" || eArgs[0] == "--help") {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_ROUTEPOLICY+"_"+CMD_ADD+"_"+CMD_CONDITIONS, eArgs, x); err != nil {
			return err
		}
	}

	return nil
}

type PolicyRoutePolicyAddActionsCommand struct {
	policyName    string
	statementName string
}

func NewPolicyRoutePolicyAddActionsCommand(pName string, sName string) *PolicyRoutePolicyAddActionsCommand {
	return &PolicyRoutePolicyAddActionsCommand{
		policyName:    pName,
		statementName: sName,
	}
}

func (x *PolicyRoutePolicyAddActionsCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_ACTIONS)
	parser := flags.NewParser(&actionOpts, flags.Default)
	parser.Usage = "policy routepolicy add <routing policy name> <statement name> actions [OPTIONS]"
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}
	if len(eArgs) == 0 {
		return fmt.Errorf("usage: policy routepolicy add <routing policy name> <statement name> actions [OPTIONS]")
	} else if !(eArgs[0] == "-h" || eArgs[0] == "--help") {
		if err := requestGrpc(CMD_POLICY+"_"+CMD_ROUTEPOLICY+"_"+CMD_ADD+"_"+CMD_ACTIONS, eArgs, x); err != nil {
			return err
		}
	}
	return nil
}

type PolicyRoutePolicyDelCommand struct{}

func (x *PolicyRoutePolicyDelCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_DEL)
	if len(eArgs) > 0 && !(eArgs[0] == "-h" || eArgs[0] == "--help" || eArgs[0] == "all") {
		if len(eArgs) > 2 {
			return fmt.Errorf("Argument can not be entered: %s", eArgs[2:])
		}
		if err := requestGrpc(CMD_POLICY+"_"+CMD_ROUTEPOLICY+"_"+CMD_DEL, eArgs, nil); err != nil {
			return err
		}
		return nil
	}
	parser := flags.NewParser(nil, flags.Default)
	parser.Usage = "policy routepolicy del <routing policy name> [<statement name>],\n  gobgp policy routepolicy del"
	parser.AddCommand(CMD_ALL, "subcommand to delete all routing policy", "", &PolicyRoutePolicyDelAllCommand{})
	if _, err := parser.ParseArgs(eArgs); err != nil {
		os.Exit(1)
	}
	return nil
}

type PolicyRoutePolicyDelAllCommand struct{}

func (x *PolicyRoutePolicyDelAllCommand) Execute(args []string) error {
	eArgs := extractArgs(CMD_ALL)
	if len(eArgs) > 0 {
		return fmt.Errorf("Argument can not be entered: %s", eArgs)
	}
	if err := requestGrpc(CMD_POLICY+"_"+CMD_ROUTEPOLICY+"_"+CMD_DEL, eArgs, nil); err != nil {
		return err
	}
	return nil
}
