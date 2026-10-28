#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <cstdlib>
#include <cstdio>
#include <filesystem>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

using initialize_fn = int (*)(const char*, const char*, int, const char**, const char**, void**, unsigned int*);
using execute_fn = int (*)(void*, unsigned int, unsigned int, const char**, const char*, unsigned int*);
using shutdown_fn = int (*)(void*, unsigned int);

static void* symbol(void* library, const char* name)
{
    void* address = dlsym(library, name);
    if (!address)
        throw std::runtime_error(std::string("PowerShell runtime is missing hosting API: ") + name);
    return address;
}

static void addAssemblies(const fs::path& directory, std::set<std::string>& names, std::string& paths)
{
    for (const auto& entry : fs::directory_iterator(directory))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".dll" &&
            names.insert(entry.path().filename().string()).second)
        {
            if (!paths.empty()) paths += ":";
            paths += entry.path().string();
        }
    }
}

int main(int argc, char** argv)
{
    try
    {
        const char* configuredHome = std::getenv("AAD_AUTHENTICATION_POWERSHELL_HOME");
        if (!configuredHome || !*configuredHome)
            throw std::runtime_error("Set AAD_AUTHENTICATION_POWERSHELL_HOME to the calling PowerShell's $PSHOME.");
        const fs::path home = fs::canonical(configuredHome);

        uint32_t size = 0;
        _NSGetExecutablePath(nullptr, &size);
        std::vector<char> buffer(size);
        if (_NSGetExecutablePath(buffer.data(), &size) != 0)
            throw std::runtime_error("Unable to resolve the broker launcher path.");
        const fs::path executable = fs::canonical(buffer.data());
        const fs::path module = executable.parent_path().parent_path().parent_path();
        const fs::path shared = module / "shared" / "netstandard2.0";
        const fs::path assembly = module / "bin" / "AadAuthenticationFactory.MacBroker.dll";
#if defined(__aarch64__)
        const fs::path native = module / "runtimes" / "osx-arm64" / "native";
#else
        const fs::path native = module / "runtimes" / "osx-x64" / "native";
#endif
        if (!fs::is_regular_file(assembly))
            throw std::runtime_error("The broker helper assembly is missing.");

        void* library = dlopen((home / "libcoreclr.dylib").c_str(), RTLD_NOW | RTLD_GLOBAL);
        if (!library)
            throw std::runtime_error(std::string("Unable to load PowerShell's .NET runtime: ") + dlerror());
        auto initialize = reinterpret_cast<initialize_fn>(symbol(library, "coreclr_initialize"));
        auto execute = reinterpret_cast<execute_fn>(symbol(library, "coreclr_execute_assembly"));
        auto shutdown = reinterpret_cast<shutdown_fn>(symbol(library, "coreclr_shutdown"));

        std::set<std::string> names;
        std::string trustedAssemblies;
        // Prefer PowerShell's framework assemblies; add only missing module dependencies.
        addAssemblies(home, names, trustedAssemblies);
        addAssemblies(shared, names, trustedAssemblies);
        std::string appPaths = assembly.parent_path().string() + ":" + shared.string();
        std::string nativePaths = native.string() + ":" + home.string();
        std::string homePath = home.string();
        const char* keys[] = {
            "TRUSTED_PLATFORM_ASSEMBLIES", "APP_PATHS", "NATIVE_DLL_SEARCH_DIRECTORIES",
            "APP_CONTEXT_BASE_DIRECTORY"
        };
        const char* values[] = {
            trustedAssemblies.c_str(), appPaths.c_str(), nativePaths.c_str(), homePath.c_str()
        };
        void* handle = nullptr;
        unsigned int domain = 0;
        int status = initialize(executable.c_str(), "AadAuthenticationFactory.MacBroker", 4,
            keys, values, &handle, &domain);
        if (status < 0)
            throw std::runtime_error("PowerShell runtime initialization failed: " + std::to_string(status));

        std::vector<const char*> arguments(argv + 1, argv + argc);
        unsigned int exitCode = 1;
        status = execute(handle, domain, static_cast<unsigned int>(arguments.size()), arguments.data(),
            assembly.c_str(), &exitCode);
        const int shutdownStatus = shutdown(handle, domain);
        if (status < 0 || shutdownStatus < 0)
            throw std::runtime_error("PowerShell runtime execution/shutdown failed: " +
                std::to_string(status) + "/" + std::to_string(shutdownStatus));
        return static_cast<int>(exitCode);
    }
    catch (const std::exception& error)
    {
        std::fprintf(stderr, "Mac broker host: %s\n", error.what());
        return 1;
    }
}
