# HookSharp

Program that detects possible hooks made by the remote process.
We do this by validating the .text sections of the DLLs in our memory with the .text sections of the DLLs in the remote process memory.

### Todos

Compare the remote process DLLs .text section with the one on the drive.
