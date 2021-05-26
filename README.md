# HookSharp

Program that detects hooks made in the remote process.
We do this by validating the .text sections of the DLLs in our memory with the .text sections of the DLLs in the remote process memory.
If a module is not found in our process we will load it by using the LoadLibraryExW function through PInvoke.
