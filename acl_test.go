package main

import (
	"testing"
	"reflect"
	"net"
	"github.com/alexey-sveshnikov/go-socks5"
	"context"
)

var testYamlDocument = `- from:
   - 0.0.0.0/0
  to:
   - 127.0.0.1/32
   - 127.0.0.2/32
  port:
   - 443
- to:
   - 192.168.0.1/32
   - 192.168.0.0/24
  port:
   - 443`

var testYamlRules = []YamlAclItem{
	YamlAclItem{
		From: []string{"0.0.0.0/0"},
		To: []string{"192.168.0.0/24", "8.8.8.8/32"},
		Port: []int{80, 443},
	},
	YamlAclItem{
		From: []string{"127.0.0.1/32"},
		To: []string{"10.10.10.1/32", "10.9.0.0/16"},
		Port: []int{},
	},
}

func TestYamlFileParsing(t *testing.T) {

	rules, err := ParseYamlRules([]byte(testYamlDocument))

	if err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	if len(*rules) != 2 {
		t.Fatal()
	}

	rule1 := (*rules)[0]

	if !reflect.DeepEqual(rule1.From, []string{"0.0.0.0/0"}) {
		t.Fatal()
	}
	if !reflect.DeepEqual(rule1.To, []string{"127.0.0.1/32", "127.0.0.2/32"}) {
		t.Fatal()
	}
	if !reflect.DeepEqual(rule1.Port, []int{443}) {
		t.Fatal()
	}
}


func TestYamlRulesParsing(t *testing.T) {
	checker := NewRuleChecker(&testYamlRules)

	rule1 := checker.acl[0]

	expected := []net.IPNet{
		net.IPNet{
			net.ParseIP("0.0.0.0"),
			net.CIDRMask(0, 32),
		},
	}
	if !reflect.DeepEqual(rule1.fromNets, expected) {
		t.Fatal()
	}

	expected = []net.IPNet{
		net.IPNet{
			net.ParseIP("192.168.0.0"),
			net.CIDRMask(24, 32),
		},
		net.IPNet{
			net.ParseIP("8.8.8.8"),
			net.CIDRMask(32, 32),
		},
	}
	if !reflect.DeepEqual(rule1.toNets, expected) {
		t.Fatal()
	}

	if !reflect.DeepEqual(rule1.ports, []int{80, 443}) {
		t.Fatal()
	}
}

func TestRuleCheckerInvalidCommands(t *testing.T) {
	checker := NewRuleChecker(&testYamlRules)

	for _, command := range([]uint8{socks5.BindCommand, socks5.AssociateCommand}) {
		req := socks5.Request{
			Command: command,
		}
		var ctx context.Context

		ctx, result := checker.Allow(ctx, &req)

		if result {
			t.Fatalf("Expected to refuse command %d", command)
		}
	}
}

func TestRuleChecker(t *testing.T) {
	okRequests := []socks5.Request{
		socks5.Request{
			Command: socks5.ConnectCommand,
			RemoteAddr: &socks5.AddrSpec{
				IP: net.ParseIP("127.0.0.1"),
			},
			DestAddr: &socks5.AddrSpec{
				IP: net.ParseIP("8.8.8.8"),
				Port: 443,
			},
		},
	}

	failRequests := []socks5.Request{
		socks5.Request{
			Command: socks5.ConnectCommand,
			RemoteAddr: &socks5.AddrSpec{
				IP: net.ParseIP("127.0.0.1"),
			},
			DestAddr: &socks5.AddrSpec{
				IP: net.ParseIP("8.8.8.9"), // doesn't match ACL
				Port: 443,
			},
		},
		socks5.Request{
			Command: socks5.ConnectCommand,
			RemoteAddr: &socks5.AddrSpec{
				IP: net.ParseIP("127.0.0.1"),
			},
			DestAddr: &socks5.AddrSpec{
				IP: net.ParseIP("8.8.8.8"),
				Port: 449, // doesn't match ACL
			},
		},
		socks5.Request{
			Command: socks5.ConnectCommand,
			RemoteAddr: &socks5.AddrSpec{
				IP: net.ParseIP("192.168.0.1"),
			},
			DestAddr: &socks5.AddrSpec{
				IP: net.ParseIP("10.10.10.1"), // allowed only from 127.0.0.1
				Port: 443,
			},
		},
	}

	checker := NewRuleChecker(&testYamlRules)
	var ctx context.Context

	for reqIndex, req := range(okRequests) {
		_, allowed := checker.Allow(ctx, &req)

		if !allowed {
			t.Fatalf("Expected to pass request %d", reqIndex)
		}
	}

	for reqIndex, req := range(failRequests) {
		_, allowed := checker.Allow(ctx, &req)

		if allowed {
			t.Fatalf("Expected to reject request %d", reqIndex)
		}
	}
}
