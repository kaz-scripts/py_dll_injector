from ctypes import *
from ctypes.wintypes import *
import subprocess
import argparse
from pathlib import Path

# DLLインジェクション関数
def dll_inject(exe_path, dll_path):
    # リモートプロセスの起動
    proc = subprocess.Popen(exe_path)
    pid = proc.pid

    # プロセスハンドルの取得
    VM_READ, VM_WRITE, VM_OPERATION = 0x0010, 0x0020, 0x0008
    DesiredAccess = VM_READ | VM_WRITE | VM_OPERATION
    kernel32 = WinDLL("kernel32")

    handle = kernel32.OpenProcess(DesiredAccess, False, pid)
    if not handle:
        print(f"エラー: プロセスハンドルの取得に失敗しました。GetLastError: {kernel32.GetLastError()}")
        return

    print(f"プロセスハンドル: {hex(handle)}")
    print(f"GetLastError: {kernel32.GetLastError()}\n")

    # プロセスへのメモリ割り当て（VirtualAllocEx）
    size = len(dll_path) + 1
    MEM_COMMIT = 0x1000 | 0x2000
    PAGE_READWRITE = 0x04

    kernel32.VirtualAllocEx.restype = LPVOID
    mem_address = kernel32.VirtualAllocEx(handle, 0, size, MEM_COMMIT, PAGE_READWRITE)
    if not mem_address:
        print(f"エラー: メモリの割り当てに失敗しました。GetLastError: {kernel32.GetLastError()}")
        return

    print(f"VirtualAllocExの戻り値: {hex(mem_address)}")
    print(f"GetLastError: {kernel32.GetLastError()}\n")

    # 割り当てたメモリにDLLのパスをコピー（WriteProcessMemory）
    kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCVOID, c_size_t, POINTER(c_size_t)]
    kernel32.WriteProcessMemory.restype = BOOL
    written = c_size_t(0)
    ret = kernel32.WriteProcessMemory(handle, mem_address, dll_path.encode(), size, byref(written))
    if not ret:
        print(f"エラー: プロセスメモリの書き込みに失敗しました。GetLastError: {kernel32.GetLastError()}")
        return

    print(f"WriteProcessMemoryが{'成功しました。' if ret != 0 else '失敗しました。'} ({ret})")
    print(f"GetLastError: {kernel32.GetLastError()}\n")

    # LoadLibrary関数のアドレスの取得（GetModuleHandleA）
    kernel32.GetModuleHandleA.restype = HMODULE
    h_module = kernel32.GetModuleHandleA(b"kernel32.dll")
    if not h_module:
        print(f"エラー: モジュールハンドルの取得に失敗しました。GetLastError: {kernel32.GetLastError()}")
        return

    print(f"kernel32.dllのモジュールハンドル: {hex(h_module)}")
    print(f"GetLastError: {kernel32.GetLastError()}\n")

    kernel32.GetProcAddress.argtypes = (HMODULE, LPCSTR)
    kernel32.GetProcAddress.restype = LPVOID
    func_addr = kernel32.GetProcAddress(h_module, b"LoadLibraryA")
    if not func_addr:
        print(f"エラー: 関数アドレスの取得に失敗しました。GetLastError: {kernel32.GetLastError()}")
        return

    print(f"LoadLibraryA関数のアドレス: {hex(func_addr)}")
    print(f"GetLastError: {kernel32.GetLastError()}\n")

    # 対象プロセスでリモートスレッドの実行（CreateRemoteThread）
    kernel32.CreateRemoteThread.argtypes = [HANDLE, LPVOID, c_size_t, LPVOID, LPVOID, DWORD, POINTER(c_size_t)]
    thread_id = c_size_t(0)
    thread_handle = kernel32.CreateRemoteThread(handle, None, 0, func_addr, mem_address, 0, byref(thread_id))
    if not thread_handle:
        print(f"エラー: リモートスレッドの作成に失敗しました。GetLastError: {kernel32.GetLastError()}")
        return

    print(f"CreateRemoteThreadの戻り値: {hex(thread_handle)}")
    print(f"GetLastError: {kernel32.GetLastError()}\n")

    print("DLLのインジェクションが成功しました")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DLLインジェクションツール')
    parser.add_argument('exe_path', type=str, help='実行ファイルのパス')
    parser.add_argument('dll_path', type=str, help='DLLのパス')

    args = parser.parse_args()
    exe_path = args.exe_path
    dll_path = str(Path(args.dll_path).resolve())
    print(exe_path,dll_path)
    dll_inject(exe_path, dll_path)
