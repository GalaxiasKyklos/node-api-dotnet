// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using Xunit;

namespace Microsoft.JavaScript.NodeApi.Test;

/// <summary>
/// Tests for <see cref="NodeApiNativeLibrary"/>, which pins already-loaded native libraries in
/// memory (Linux/macOS) so their <c>pthread_key</c> TLS destructors are never unmapped and cannot
/// dangle when a worker thread tears down (SIGSEGV / exit 139). See the worker_teardown regression
/// case for the end-to-end host-module scenario; these tests cover the public pinning API contract
/// and exercise the underlying <c>dlopen(RTLD_NODELETE)</c> primitive against a real loaded library.
/// </summary>
public class NativeLibraryPinningTests
{
    private static bool IsAffectedPlatform =>
        RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
        RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

    [Fact]
    public void PreventUnload_NullOrEmpty_ReturnsFalse()
    {
        Assert.False(NodeApiNativeLibrary.PreventUnload(null!));
        Assert.False(NodeApiNativeLibrary.PreventUnload(string.Empty));
    }

    [Fact]
    public void PreventUnload_NotLoadedLibrary_ReturnsFalse()
    {
        // A library that is not loaded is resolved with RTLD_NOLOAD, so dlopen returns null and no
        // new copy is loaded. On unaffected platforms (Windows) this is always a no-op returning
        // false. Either way the result must be false.
        Assert.False(NodeApiNativeLibrary.PreventUnload(
            "node-api-dotnet-this-library-does-not-exist.so"));
    }

    [Fact]
    public void PreventUnload_LoadedRuntimeLibrary_ReturnsTrueOnAffectedPlatforms()
    {
        string? loadedRuntimeLibraryPath = FindLoadedRuntimeLibraryPath();

        if (!IsAffectedPlatform)
        {
            // Pinning is a no-op on Windows; the API must report that nothing was pinned even if a
            // matching module name happens to be loaded.
            Assert.False(NodeApiNativeLibrary.PreventUnload(
                loadedRuntimeLibraryPath ?? "kernel32.dll"));
            return;
        }

        // The test itself runs on the CoreCLR runtime, so libcoreclr (or another runtime native
        // library) is loaded and must be found; a null here indicates a real problem locating it.
        Assert.NotNull(loadedRuntimeLibraryPath);

        // Pinning an already-loaded library must succeed, and must remain successful when repeated
        // (the pin is idempotent; the extra, never-released reference simply blocks a later dlclose).
        Assert.True(NodeApiNativeLibrary.PreventUnload(loadedRuntimeLibraryPath!));
        Assert.True(NodeApiNativeLibrary.PreventUnload(loadedRuntimeLibraryPath!));
    }

    [Fact]
    public void PreventRuntimeLibrariesUnload_DoesNotThrow_AndIsIdempotent()
    {
        // Best-effort and idempotent on every platform: it pins the runtime's native libraries on
        // Linux/macOS and is a no-op on Windows. It must never throw.
        NodeApiNativeLibrary.PreventRuntimeLibrariesUnload();
        NodeApiNativeLibrary.PreventRuntimeLibrariesUnload();
    }

    // Finds the full path of a loaded .NET runtime native library (for example libcoreclr). It
    // first walks the current process's loaded modules, then falls back to the well-known runtime
    // directory. Returns null if none is found.
    private static string? FindLoadedRuntimeLibraryPath()
    {
        string[] prefixes =
        {
            "libcoreclr",
            "libclrjit",
            "libhostpolicy",
            "libSystem.Native",
        };

        try
        {
            foreach (ProcessModule module in Process.GetCurrentProcess().Modules
                .Cast<ProcessModule>())
            {
                string fileName = module.ModuleName ?? string.Empty;
                if (prefixes.Any(p => fileName.StartsWith(p, StringComparison.Ordinal)) &&
                    !string.IsNullOrEmpty(module.FileName))
                {
                    return module.FileName;
                }
            }
        }
        catch (Exception)
        {
            // Module enumeration can be unavailable on some platforms/configurations; fall through.
        }

        // Fall back to the loaded CLR native library in the runtime directory.
        string extension = RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? ".dylib" : ".so";
        string candidate = System.IO.Path.Combine(
            RuntimeEnvironment.GetRuntimeDirectory(), "libcoreclr" + extension);
        return System.IO.File.Exists(candidate) ? candidate : null;
    }
}
