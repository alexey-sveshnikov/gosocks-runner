package main

import (
	"context"
	"github.com/alexey-sveshnikov/go-socks5"
	"fmt"
	"strings"
	"strconv"
	"net"
	"gopkg.in/yaml.v2"
)

type YamlAclItem struct {
	From []string `yaml:"from"`
	To   []string `yaml:"to"`
	Port []int
}

func ParseYamlRules(data []byte) (*[]YamlAclItem, error) {
	var result = []YamlAclItem{}
	err := yaml.Unmarshal(data, &result);
	if err != nil {
		return nil, fmt.Errorf("error while parsing YAML: %s", err)
	}
	//spew.Dump(result)
	return &result, nil
}

type AclItem struct {
	fromNets []net.IPNet
	toNets[]net.IPNet
	ports    []int
}

func parseAddr(value string) (*net.IPNet, error) {
	chunks := strings.SplitN(value, "/", 2)
	if len(chunks) != 2 {
		return nil, fmt.Errorf("Can't parse acl item %s (expected to receive n.n.n.n/n format)", value)
	}

	addr := net.ParseIP(chunks[0])
	if addr == nil {
		return nil, fmt.Errorf("Can't parse IP %s", chunks[0])
	}

	maskInt, err := strconv.Atoi(chunks[1]);
	if err != nil {
		return nil, fmt.Errorf("Can't parse netmask length %s", chunks[1])
	}

	netmaskLength := 32
	if addr.To4() == nil {
		netmaskLength = 128
	}

	mask := net.CIDRMask(maskInt, netmaskLength)
	return &net.IPNet{addr, mask}, nil
}

func ParseYamlAclItem(item *YamlAclItem) (*AclItem, error) {
	var newItem = AclItem{}

	for _, value := range item.From {
		fromNet, err := parseAddr(value);
		if err != nil {
			return nil, err
		}

		newItem.fromNets = append(newItem.fromNets, *fromNet)
	}

	for _, value := range item.To {
		toNet, err := parseAddr(value);
		if err != nil {
			return nil, err
		}

		newItem.toNets = append(newItem.toNets, *toNet)
	}

	newItem.ports = item.Port

	return &newItem, nil
}

type RuleChecker struct {
	acl []AclItem
}

func (r *RuleChecker) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	if (req.Command != socks5.ConnectCommand) {
		return ctx, false
	}

	for _, aclItem := range (r.acl) {
		for _, fromNet := range (aclItem.fromNets) {
			if fromNet.Contains(req.RemoteAddr.IP) {
				//fmt.Printf("fromNet %s contains remote addr %s\n",
				//	fromNet, req.RemoteAddr)

				for _, toNet := range(aclItem.toNets) {
					if toNet.Contains(req.DestAddr.IP) {
						//fmt.Printf("toNet %s contains dest addr %s\n",
						//	toNet, req.DestAddr)

						if len(aclItem.ports) == 0 {
							return ctx, true
						}

						for _, port := range aclItem.ports {
							if port == req.DestAddr.Port {
								return ctx, true
							}
						}
					}
				}
			}
		}
	}
	return ctx, false
}

func NewRuleChecker(yamlItems *[]YamlAclItem) *RuleChecker {
	var acl []AclItem;
	if yamlItems != nil {
		for _, item := range *yamlItems {
			aclItem, err := ParseYamlAclItem(&item);
			if err != nil {
				panic(err)
			}
			acl = append(acl, *aclItem)
		}
	}

	return &RuleChecker{acl}
}
