package main

import (
	"github.com/alexey-sveshnikov/go-socks5"
	"io"
	"bufio"
	"fmt"
	"strings"
)

func LoadCredentials(src io.Reader) (*socks5.StaticCredentials, error) {
	result := socks5.StaticCredentials{}
	scanner := bufio.NewScanner(src)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}

		if fields[0][0] == '#' {
			continue
		}

		if len(fields) < 2 {
			return nil, fmt.Errorf("Can't parse credentials file string %s", scanner.Text())
		}

		result[fields[0]] = fields[1]
	}
	return &result, nil
}
