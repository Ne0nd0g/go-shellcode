# go-shellcode

`go-shellcode` is a repository of Windows Shellcode runners and supporting utuilies. The applications load and execute Shellcode using various API calls or techniques.

The available Shellcode runners include:

* [CreateRemoteThread](#CreateRemoteThred)
* [CreateRemoteThreadNative](#CreateRemoteThreadNative)
* [CreateThread](#CreateThread)
* [CreateThreadNative](#CreateThreadNative)
* [RtlCreateUserThread](#RtlCreateUserThread)
* [Syscall](#Syscall)

## CreateRemoteThread

This application leverages the Windows [CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) function from `Kernel32.dll` to execute shellocde in a remote process. The application requires that the target process to inject into is already running. The targe Process Identifier (PID) can provided at runtime for testing using the `-pid` command line flag. Hardcode the PID in the following line of code for operational use by replacing the `0` with your target PID:

`pid := flag.Int("pid", 0, "Process ID to inject shellcode into")`

This application leverages functions from the `golang.org/x/sys/windows` package, where feasible, like the [`windows.OpenProcess()`](https://github.com/golang/sys/blob/a7d97aace0b0/windows/zsyscall_windows.go#L1197). The application can be compiled wit the following command on Windows host from the project's root directory:

`set GOOS=windows GOARCH=amd64;go build -o CreateRemoteThread.exe .\cmd\CreateRemoteThread\main.go`

## CreateRemoteThreadNative

This application leverages the Windows [CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) function from `Kernel32.dll` to execute shellocde in a remote process. The application requires that the target process to inject into is already running. The targe Process Identifier (PID) can provided at runtime for testing using the `-pid` command line flag. Hardcode the PID in the following line of code for operational use by replacing the `0` with your target PID:

`pid := flag.Int("pid", 0, "Process ID to inject shellcode into")`

This application **DOES NOT** leverages functions from the `golang.org/x/sys/windows` package. The most significant difference is that this application loads all the necessary DLLs and Procedures itself and uses the procedure's Call() function. The application can be compiled wit the following command on Windows host from the project's root directory:

`set GOOS=windows GOARCH=amd64;go build -o CreateRemoteThreadNative.exe .\cmd\CreateRemoteThreadNative\main.go`

## CreateThread

This application leverages the Windows [CreateThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread) function from `Kernel32.dll` to execute shellcode within this application's process. This is usefull when you want to avoid remote process injection. This application leverages functions from the `golang.org/x/sys/windows` package, where feasible, like the [windows.VirtualAlloc()`](https://github.com/golang/sys/blob/a7d97aace0b0/windows/zsyscall_windows.go#L1712). The application can be compiled wit the following command on Windows host from the project's root directory:

`set GOOS=windows GOARCH=amd64;go build -o CreateThread.exe .\cmd\CreateThread\main.go`

## CreateThreadNative

This application leverages the Windows [CreateThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread) function from the `Kernel32.dll` to execute shellcode within this application's process. This is usefull when you want to avoid remote process injection. This application **DOES NOT** leverages functions from the `golang.org/x/sys/windows` package. The most significant difference is that this application loads all the necessary DLLs and Procedures itself and uses the procedure's Call() function. The application can be compiled wit the following command on Windows host from the project's root directory:

`set GOOS=windows GOARCH=amd64;go build -o CreateThreadNative.exe .\cmd\CreateThreadNative\main.go`

## RtlCreateUserThread

This application leverages the Windows [RtlCreateUserThread](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FRtlCreateUserThread.html) function from `ntdll.dll` to execute shellocde in a remote process. The application requires that the target process to inject into is already running. The targe Process Identifier (PID) can provided at runtime for testing using the `-pid` command line flag. Hardcode the PID in the following line of code for operational use by replacing the `0` with your target PID:

`pid := flag.Int("pid", 0, "Process ID to inject shellcode into")`

This application **DOES NOT** leverages functions from the `golang.org/x/sys/windows` package. The most significant difference is that this application loads all the necessary DLLs and Procedures itself and uses the procedure's Call() function. The application can be compiled wit the following command on Windows host from the project's root directory:

`set GOOS=windows GOARCH=amd64;go build -o RtlCreateUserThread.exe .\cmd\RtlCreateUserThread\main.go`

## Syscall

This application executes Shellcode in the current running proccess by making a Syscall on the Shellcode's entry point. This application **DOES NOT** leverages functions from the `golang.org/x/sys/windows` package. The application can be compiled wit the following command on Windows host from the project's root directory:

`set GOOS=windows GOARCH=amd64;go build -o Syscall.exe .\cmd\Syscall\main.go`
