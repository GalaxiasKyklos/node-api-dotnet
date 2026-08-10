// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#if !(NETFRAMEWORK || NETSTANDARD)

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Microsoft.JavaScript.NodeApi.DotNetHost;

/// <summary>
/// Pins native shared libraries in memory (Linux/macOS) so the OS never unloads them,
/// avoiding a worker-thread teardown crash caused by dangling <c>pthread_key</c> destructors.
/// </summary>
/// <remarks>
/// A native library can register per-thread cleanup with the OS via
/// <c>pthread_key_create(&amp;key, destructor)</c>. glibc's <c>__nptl_deallocate_tsd</c> calls that
/// destructor when a thread exits. If the library that owns the destructor is unloaded
/// (<c>dlclose</c>) while a thread still holds a value for the key — as happens when a
/// <c>worker_threads</c> Worker that used native code is torn down — the destructor pointer dangles
/// into unmapped memory and the process crashes with SIGSEGV as the worker thread exits.
/// <para/>
/// Re-opening such a library with <c>RTLD_NODELETE</c> keeps it mapped for the lifetime of the
/// process, so the destructor pointer stays valid. This complements the node-api-dotnet host module
/// pin (see <c>NativeHost.PreventModuleUnload</c>): the host module pin only covers node-api-dotnet's
/// own code, while the .NET runtime and other native dependencies register their own TLS destructors.
/// </remarks>
internal static unsafe partial class NativeLibraryPinning
{
    private const int RTLD_LAZY = 0x0001;
    private const int RTLD_NOLOAD_LINUX = 0x0004;
    private const int RTLD_NODELETE_LINUX = 0x1000;
    private const int RTLD_NOLOAD_MACOS = 0x0010;
    private const int RTLD_NODELETE_MACOS = 0x0080;

    private static bool IsMacOS => RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

    private static bool IsSupported =>
        RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || IsMacOS;

    private static bool s_runtimeLibrariesPinned;

    // Basename prefixes of the .NET runtime native libraries that register pthread_key TLS
    // destructors (managed thread / finalizer cleanup, and OpenSSL thread-local state used by the
    // crypto libraries). Pinning these keeps their destructors valid across worker-thread teardown.
    private static readonly string[] s_runtimeLibraryPrefixes = new[]
    {
        "libcoreclr",
        "libclrjit",
        "libclrgc",
        "libhostpolicy",
        "libSystem.Native",
        "libSystem.Security.Cryptography.Native",
        "libSystem.Net.Security.Native",
    };

    /// <summary>
    /// Pins the already-loaded .NET runtime native libraries so their per-thread TLS destructors
    /// remain mapped for the lifetime of the process. Best-effort: failures are traced, not thrown.
    /// </summary>
    internal static void PinLoadedRuntimeLibraries()
    {
        if (s_runtimeLibrariesPinned || !IsSupported)
        {
            return;
        }

        s_runtimeLibrariesPinned = true;

        try
        {
            foreach (string path in EnumerateLoadedLibraries())
            {
                string name = GetFileName(path);
                if (MatchesRuntimeLibrary(name) && TryPinByPath(path))
                {
                    NativeHost.Trace($"    Pinned runtime native library ({name}).");
                }
            }
        }
        catch (Exception ex)
        {
            NativeHost.Trace("    Failed to pin runtime native libraries: " + ex);
        }
    }

    /// <summary>
    /// Pins a specific native library (by path or already-loaded name) with <c>RTLD_NODELETE</c>.
    /// </summary>
    /// <returns>True if the library was found loaded and pinned; otherwise false.</returns>
    internal static bool PinLibrary(string libraryNameOrPath)
    {
        if (string.IsNullOrEmpty(libraryNameOrPath) || !IsSupported)
        {
            return false;
        }

        try
        {
            return TryPinByPath(libraryNameOrPath);
        }
        catch (Exception ex)
        {
            NativeHost.Trace($"    Failed to pin native library '{libraryNameOrPath}': " + ex);
            return false;
        }
    }

    private static bool MatchesRuntimeLibrary(string fileName)
    {
        foreach (string prefix in s_runtimeLibraryPrefixes)
        {
            if (fileName.StartsWith(prefix, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    // RTLD_NOLOAD resolves an already-loaded library without loading a new copy; if it is not
    // loaded, dlopen returns null and this is a no-op. RTLD_NODELETE keeps it mapped for the
    // process lifetime. The extra (never released) reference also blocks a later dlclose.
    private static bool TryPinByPath(string path)
    {
        int flags = RTLD_LAZY | (IsMacOS ?
            RTLD_NOLOAD_MACOS | RTLD_NODELETE_MACOS :
            RTLD_NOLOAD_LINUX | RTLD_NODELETE_LINUX);

        nint utf8 = Marshal.StringToCoTaskMemUTF8(path);
        try
        {
            return DlOpen(utf8, flags) != default;
        }
        finally
        {
            Marshal.FreeCoTaskMem(utf8);
        }
    }

    private static string GetFileName(string path)
    {
        int slash = path.LastIndexOf('/');
        return slash >= 0 ? path.Substring(slash + 1) : path;
    }

    private static IEnumerable<string> EnumerateLoadedLibraries()
    {
        return IsMacOS ? EnumerateLoadedLibrariesMacOS() : EnumerateLoadedLibrariesLinux();
    }

    // On Linux, walk the dynamic linker's list of loaded objects. Names are collected during
    // iteration and returned afterward: dl_iterate_phdr holds the loader lock, so calling dlopen
    // from inside the callback would deadlock. The dlpi_name pointers remain valid after iteration
    // because they reference strings owned by the loaded objects.
    private static IEnumerable<string> EnumerateLoadedLibrariesLinux()
    {
        var names = new List<string>();
        var handle = GCHandle.Alloc(names);
        try
        {
            DlIteratePhdr(&CollectLibraryName, (void*)GCHandle.ToIntPtr(handle));
        }
        finally
        {
            handle.Free();
        }

        return names;
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
    private static int CollectLibraryName(dl_phdr_info* info, nuint size, void* data)
    {
        try
        {
            if (info != null && info->dlpi_name != default)
            {
                string? name = Marshal.PtrToStringUTF8(info->dlpi_name);
                if (!string.IsNullOrEmpty(name))
                {
                    var list = (List<string>)GCHandle.FromIntPtr((nint)data).Target!;
                    list.Add(name!);
                }
            }
        }
        catch
        {
            // Never let an exception propagate through the native dl_iterate_phdr callback.
        }

        return 0;
    }

    private static IEnumerable<string> EnumerateLoadedLibrariesMacOS()
    {
        uint count = DyldImageCount();
        for (uint i = 0; i < count; i++)
        {
            nint namePtr = DyldGetImageName(i);
            if (namePtr != default)
            {
                string? name = Marshal.PtrToStringUTF8(namePtr);
                if (!string.IsNullOrEmpty(name))
                {
                    yield return name!;
                }
            }
        }
    }

    // dlopen is exported by libSystem on macOS. On Linux it is exported by libc.so.6 on
    // glibc >= 2.34, but by libdl.so.2 on older glibc versions.
    private static nint DlOpen(nint fileName, int flags)
    {
        if (IsMacOS)
        {
            return DlOpenLibSystem(fileName, flags);
        }

        try
        {
            return DlOpenLibc(fileName, flags);
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException)
        {
            return DlOpenLibdl(fileName, flags);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct dl_phdr_info
    {
        public nint dlpi_addr;
        public nint dlpi_name;
        // Remaining fields (phdr table pointer/count, etc.) are not needed here.
    }

    [LibraryImport("libc.so.6", EntryPoint = "dl_iterate_phdr")]
    private static partial int DlIteratePhdr(
        delegate* unmanaged[Cdecl]<dl_phdr_info*, nuint, void*, int> callback, void* data);

    [LibraryImport("libc.so.6", EntryPoint = "dlopen")]
    private static partial nint DlOpenLibc(nint filename, int flags);

    [LibraryImport("libdl.so.2", EntryPoint = "dlopen")]
    private static partial nint DlOpenLibdl(nint filename, int flags);

    [LibraryImport("/usr/lib/libSystem.B.dylib", EntryPoint = "dlopen")]
    private static partial nint DlOpenLibSystem(nint filename, int flags);

    [LibraryImport("/usr/lib/libSystem.B.dylib", EntryPoint = "_dyld_image_count")]
    private static partial uint DyldImageCount();

    [LibraryImport("/usr/lib/libSystem.B.dylib", EntryPoint = "_dyld_get_image_name")]
    private static partial nint DyldGetImageName(uint index);
}

#endif
