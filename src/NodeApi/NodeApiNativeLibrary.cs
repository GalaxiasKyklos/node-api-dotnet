// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.JavaScript.NodeApi;

/// <summary>
/// Helpers for managing native libraries loaded alongside node-api-dotnet.
/// </summary>
public static class NodeApiNativeLibrary
{
    /// <summary>
    /// Pins an already-loaded native library in memory (Linux/macOS) so the OS never unloads it,
    /// preventing a worker-thread teardown crash caused by a dangling <c>pthread_key</c> destructor.
    /// </summary>
    /// <param name="libraryNameOrPath">
    /// The path, or already-loaded name, of the native library to pin (for example an application's
    /// native authentication or cryptography dependency).
    /// </param>
    /// <returns>
    /// True if the library was found loaded and pinned; false if it was not loaded, if the platform
    /// is not affected (Windows), or if pinning is not supported on the current target framework.
    /// </returns>
    /// <remarks>
    /// A native library can register per-thread cleanup with the OS via
    /// <c>pthread_key_create(&amp;key, destructor)</c>; glibc's <c>__nptl_deallocate_tsd</c> calls that
    /// destructor when a thread exits. If the library is unloaded (<c>dlclose</c>) while a thread
    /// still holds a value for the key — as can happen when a <c>worker_threads</c> Worker that used
    /// the library is torn down — the destructor pointer dangles into unmapped memory and the process
    /// crashes with SIGSEGV (<c>exit 139</c>) as the worker thread exits.
    /// <para/>
    /// node-api-dotnet already pins its own host module and the .NET runtime's native libraries.
    /// Call this method during application startup for any additional native dependency your
    /// application loads that registers a TLS destructor, so it is kept mapped for the process
    /// lifetime. The library must already be loaded when this is called. This is a no-op on Windows.
    /// </remarks>
    public static bool PreventUnload(string libraryNameOrPath)
    {
#if NETFRAMEWORK || NETSTANDARD
        _ = libraryNameOrPath;
        return false;
#else
        return DotNetHost.NativeLibraryPinning.PinLibrary(libraryNameOrPath);
#endif
    }

    /// <summary>
    /// Pins the .NET runtime's already-loaded native libraries (for example the CLR and its
    /// cryptography libraries) in memory on Linux/macOS, so their <c>pthread_key</c> TLS
    /// destructors are never unmapped and cannot dangle when a worker thread tears down.
    /// </summary>
    /// <remarks>
    /// node-api-dotnet calls this automatically during host initialization; it is exposed publicly
    /// so applications can also invoke it explicitly. It is idempotent and a no-op on Windows.
    /// </remarks>
    public static void PreventRuntimeLibrariesUnload()
    {
#if NETFRAMEWORK || NETSTANDARD
        // No-op: the affected teardown crash is specific to Linux/macOS hosted-runtime scenarios.
#else
        DotNetHost.NativeLibraryPinning.PinLoadedRuntimeLibraries();
#endif
    }
}
