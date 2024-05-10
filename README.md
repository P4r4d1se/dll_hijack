修复bug后的DLLHijacker.py和劫持Windows x64的dbghelp.ll的VS2022项目。
DLLHijacker.py after fixing the bug and VS2022 project that hijacks dbghelp.ll for Windows x64
bug fix:
(1) Garbled code:
Fix: Add `encoding="utf-8"` to several writing files.
(2) When the function export table has anonymous functions, it will cause `[-]Error occur: 'NoneType' object has no attribute 'decode'`:
Fix: Add judgment on whether the function name is empty in several `for` loops.
(3) When generating C/C++ code, the absolute DLL path is not used, only the name of the DLL is used to fill `LoadLibrary()`. This is a serious bug that will cause function forwarding to fail and the functionality of the application to be affected:
Fix: Changed to automatically fill in based on the entered target DLL path.
Usage: 
python3 DLLHijacker.py /path/to/target.dll 
Original project：
https://github.com/kiwings/DLLHijacker
