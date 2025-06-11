package main

import (
	"fmt"
	"kyanos/common"
	"net"
)

func main() {
	bytes := common.NetIPToBytes(net.ParseIP("1.1.1.1"), false)
	for _, item := range bytes {
		fmt.Println(item)
	}
}
