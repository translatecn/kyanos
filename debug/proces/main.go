package main

import (
	"fmt"
	"github.com/shirou/gopsutil/process"
)

func main() {
	processes, _ := process.Processes()
	for _, proc := range processes {
		pn, _ := proc.Exe()
		fmt.Println(pn, proc.Pid)
		fmt.Println(proc.Name())
		fmt.Println(proc.Status())
		fmt.Println(proc.Cmdline())
	}
}
