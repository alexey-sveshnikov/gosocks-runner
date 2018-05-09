package main

import (
	"flag"
	"fmt"
	"github.com/alexey-sveshnikov/go-socks5"
	"io/ioutil"
	"os"
	"strconv"
	"github.com/davecgh/go-spew/spew"
)

var port int
var interfaceAddr string
var aclFile string
var credsFile string

func main() {
	flag.IntVar(&port, "port", 1080, "Port number")
	flag.StringVar(&interfaceAddr, "interface", "0.0.0.0", "Interface address")
	flag.StringVar(&aclFile, "acl", "", "ACL yaml file")
	flag.StringVar(&credsFile, "creds", "", "Credentials file")
	flag.Parse()

	conf := &socks5.Config{
	}

	if (aclFile != "") {
		var aclValues *[]YamlAclItem
		aclContents, err := ioutil.ReadFile(aclFile);
		if err != nil {
			panic(err)
		}

		aclValues, err = ParseYamlRules(aclContents); if err != nil {
			panic(err)
		}

		conf.Rules = NewRuleChecker(aclValues)
	}

	if (credsFile != "") {
		file, err := os.Open(credsFile); if err != nil {
			panic(err)
		}

		credentials, err := LoadCredentials(file); if err != nil {
			panic(err)
		}

		spew.Dump(credentials)
		conf.Credentials = credentials
	}

	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}
	bindAddrPort := interfaceAddr + ":" + strconv.Itoa(port)
	fmt.Fprintln(os.Stdout, "Listening on", bindAddrPort)

	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", bindAddrPort); err != nil {
		panic(err)
	}
}
