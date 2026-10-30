using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Broker;
using Microsoft.Identity.Client.NativeInterop;
using Microsoft.Identity.Client.Utils;

internal static class Program
{
    private const string RedirectUri = "msauth.com.msauth.unsignedapp://auth";
    private const string Usage =
        "Usage: AadAuthenticationFactory.MacBroker --probe | --startup | " +
        "(--accounts | --silent | --interactive | --sso-test) " +
        "--client-id <id> --tenant <tenant> " +
        "[--scope <scope> ...] [--login-hint <user> | --home-account-id <id>]. " +
        "Scopes are required for token requests. --sso-test performs interactive then forced silent broker authentication.";

    [DllImport("libSystem.B.dylib")]
    private static extern int pthread_main_np();

    private static int Main(string[] args)
    {
        bool moduleMode = args.Length == 1 && args[0] == "--module";
        try
        {
            if (!OperatingSystem.IsMacOS())
                throw new PlatformNotSupportedException("The broker helper requires macOS.");

            var moduleRoot = Directory.GetParent(Path.GetDirectoryName(typeof(Program).Assembly.Location)!)!.FullName;
            bool arm64 = RuntimeInformation.ProcessArchitecture == Architecture.Arm64;
            string nativePath = Path.Combine(moduleRoot, "runtimes",
                arm64 ? "osx-arm64" : "osx-x64", "native",
                arm64 ? "msalruntime_arm64.dylib" : "msalruntime.dylib");
            NativeLibrary.SetDllImportResolver(typeof(Core).Assembly, (name, _, _) =>
                name == (arm64 ? "msalruntime_arm64" : "msalruntime")
                    ? NativeLibrary.Load(nativePath) : IntPtr.Zero);

            BrokerRequest? moduleRequest = null;
            Options? options = null;
            if (moduleMode)
            {
                if (!Console.IsInputRedirected || !Console.IsOutputRedirected)
                    throw new ArgumentException("--module requires redirected stdin and stdout.");
                moduleRequest = JsonSerializer.Deserialize<BrokerRequest>(Console.In.ReadToEnd())
                    ?? throw new ArgumentException("Missing broker request.");
                moduleRequest.Validate();
            }
            else
            {
                options = ParseArguments(args);
            }
            var scheduler = MacMainThreadScheduler.Instance();
            if (pthread_main_np() != 1 || !scheduler.IsCurrentlyOnMainThread())
                throw new InvalidOperationException("The helper entry point is not on the macOS main thread.");

            using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            ConsoleCancelEventHandler cancelHandler = (_, e) =>
            {
                e.Cancel = true;
                cancellation.Cancel();
            };
            Console.CancelKeyPress += cancelHandler;
            try
            {
                // Main stays synchronous so this loop owns the process's original thread.
                Task work = scheduler.RunOnMainThreadAsync(async () =>
                {
                    try
                    {
                        if (pthread_main_np() != 1 || !scheduler.IsRunning())
                            throw new InvalidOperationException("Main-thread dispatch failed.");

                        if (moduleMode)
                        {
                            var response = await ModuleProtocol.RunAsync(moduleRequest!, cancellation.Token)
                                .ConfigureAwait(false);
                            Console.WriteLine(JsonSerializer.Serialize(response));
                        }
                        else
                        {
                            Console.Error.WriteLine(JsonSerializer.Serialize(new
                            {
                                nativeMainThread = true,
                                managedThreadId = Environment.CurrentManagedThreadId,
                                schedulerRunning = scheduler.IsRunning(),
                                runtimeDirectory = Path.GetDirectoryName(typeof(object).Assembly.Location),
                                msalAssembly = typeof(PublicClientApplication).Assembly.Location,
                                nativeRuntime = nativePath
                            }));
                            await RunAsync(options!, cancellation.Token).ConfigureAwait(false);
                        }
                    }
                    finally
                    {
                        scheduler.Stop();
                    }
                });

                scheduler.StartMessageLoop();
                work.GetAwaiter().GetResult();
                return 0;
            }
            finally
            {
                Console.CancelKeyPress -= cancelHandler;
            }
        }
        catch (Exception exception)
        {
            if (moduleMode)
            {
                Console.WriteLine(JsonSerializer.Serialize(new BrokerResponse
                {
                    Error = new BrokerError
                    {
                        Code = (exception as MsalException)?.ErrorCode ?? exception.GetType().Name,
                        Message = exception.Message,
                        InteractionRequired = exception is MsalUiRequiredException,
                        Claims = (exception as MsalUiRequiredException)?.Claims,
                        CorrelationId = (exception as MsalException)?.CorrelationId
                    }
                }));
            }
            else
            {
                Console.Error.WriteLine(JsonSerializer.Serialize(new
                {
                    error = exception.GetType().FullName,
                    errorCode = (exception as MsalException)?.ErrorCode,
                    interactionRequired = exception is MsalUiRequiredException,
                    correlationId = (exception as MsalException)?.CorrelationId,
                    message = exception.Message
                }));
            }
            return 1;
        }
    }

    private static async Task RunAsync(Options options, CancellationToken cancellationToken)
    {
        if (options.Mode == "--probe")
        {
            using var parameters = new AuthParameters(
                "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
                "https://login.microsoftonline.com/organizations");
            parameters.RequestedScopes = "https://management.azure.com/.default";
            if (parameters.RequestedScopes != "https://management.azure.com/.default")
                throw new InvalidOperationException("Native authentication parameters did not round-trip.");

            Console.WriteLine(JsonSerializer.Serialize(new { nativeImports = "ok", mode = options.Mode }));
            return;
        }

        // Fail before token acquisition if the native broker is unavailable.
        // Merely enabling WithBroker would otherwise permit browser fallback.
        using (var core = new Core())
        {
            if (options.Mode == "--startup")
            {
                Console.WriteLine(JsonSerializer.Serialize(new { brokerStartup = "ok", mode = options.Mode }));
                return;
            }
        }

        var application = PublicClientApplicationBuilder.Create(options.ClientId)
            .WithAuthority($"https://login.microsoftonline.com/{Uri.EscapeDataString(options.Tenant)}")
            .WithRedirectUri(RedirectUri)
            .WithBroker(new BrokerOptions(BrokerOptions.OperatingSystems.OSX)
            {
                Title = "AadAuthenticationFactory broker proof of concept",
                ListOperatingSystemAccounts = true
            })
            .Build();

        if (options.Mode == "--accounts" || options.Mode == "--silent" || options.HomeAccountId != null)
        {
            var accounts = (await application.GetAccountsAsync().WaitAsync(cancellationToken)
                .ConfigureAwait(false)).ToList();
            if (options.Mode == "--accounts")
            {
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    mode = options.Mode,
                    accounts = accounts.Select(account => new
                    {
                        username = account.Username,
                        homeAccountId = account.HomeAccountId.Identifier,
                        environment = account.Environment
                    })
                }));
                return;
            }

            var matches = accounts.Where(account =>
                (options.LoginHint == null || string.Equals(account.Username, options.LoginHint, StringComparison.OrdinalIgnoreCase)) &&
                (options.HomeAccountId == null || string.Equals(account.HomeAccountId.Identifier, options.HomeAccountId, StringComparison.Ordinal)))
                .ToList();
            if (matches.Count != 1)
                throw new InvalidOperationException(
                    $"Account selection matched {matches.Count} broker accounts. Use --accounts, then specify " +
                    "--login-hint or --home-account-id to select exactly one account. " +
                    "If no account is discovered, run --interactive first.");

            if (options.Mode == "--silent")
            {
                var silentResult = await application.AcquireTokenSilent(options.Scopes, matches[0])
                    .WithForceRefresh(true).ExecuteAsync(cancellationToken).ConfigureAwait(false);
                WriteResult(silentResult, "silent");
                return;
            }

            // Account discovery may resume on a pool thread; dispatch UI back to main.
            await MacMainThreadScheduler.Instance().RunOnMainThreadAsync(
                () => RunInteractiveAsync(application, options, matches[0], cancellationToken)).ConfigureAwait(false);
            return;
        }

        await RunInteractiveAsync(application, options, null, cancellationToken).ConfigureAwait(false);
    }

    private static async Task RunInteractiveAsync(
        IPublicClientApplication application, Options options, IAccount? account,
        CancellationToken cancellationToken)
    {
        if (pthread_main_np() != 1)
            throw new InvalidOperationException("Interactive broker authentication must start on the native main thread.");

        var request = application.AcquireTokenInteractive(options.Scopes);
        if (account != null)
            request = request.WithAccount(account);
        else if (options.LoginHint != null)
            request = request.WithLoginHint(options.LoginHint);

        var result = await request.ExecuteAsync(cancellationToken).ConfigureAwait(false);
        WriteResult(result, "interactive");
        if (options.Mode == "--sso-test")
        {
            if (result.Account == null)
                throw new InvalidOperationException("The broker returned no account for the silent SSO test.");

            var silentResult = await application.AcquireTokenSilent(options.Scopes, result.Account)
                .WithForceRefresh(true).ExecuteAsync(cancellationToken).ConfigureAwait(false);
            WriteResult(silentResult, "silent");
        }
    }

    private static void WriteResult(AuthenticationResult result, string stage)
    {
        var tokenSource = result.AuthenticationResultMetadata.TokenSource;
        if (tokenSource != TokenSource.Broker)
            throw new InvalidOperationException(
                $"Expected a broker token, but {stage} authentication used '{tokenSource}'. " +
                "Browser or application-cache success does not prove broker SSO.");

        // This diagnostic tool deliberately never writes access, ID, or refresh tokens.
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            stage,
            authenticated = true,
            tokenSource = tokenSource.ToString(),
            forceRefresh = stage == "silent",
            username = result.Account?.Username,
            homeAccountId = result.Account?.HomeAccountId.Identifier,
            tenantId = result.TenantId,
            scopes = result.Scopes,
            expiresOn = result.ExpiresOn,
            correlationId = result.CorrelationId
        }));
    }

    private static Options ParseArguments(string[] args)
    {
        if (args.Length == 1 && (args[0] == "--probe" || args[0] == "--startup"))
            return new Options { Mode = args[0] };

        if (args.Length == 0 ||
            (args[0] != "--accounts" && args[0] != "--silent" &&
             args[0] != "--interactive" && args[0] != "--sso-test"))
            throw new ArgumentException(Usage);

        var options = new Options { Mode = args[0] };
        var seenOptions = new HashSet<string>(StringComparer.Ordinal);
        for (int index = 1; index < args.Length; index += 2)
        {
            if (index + 1 >= args.Length || string.IsNullOrWhiteSpace(args[index + 1]))
                throw new ArgumentException(Usage);

            string value = args[index + 1];
            if (value.StartsWith("--", StringComparison.Ordinal) ||
                (args[index] != "--scope" && !seenOptions.Add(args[index])))
                throw new ArgumentException($"Missing value or duplicate option '{args[index]}'. {Usage}");

            switch (args[index])
            {
                case "--client-id": options.ClientId = value; break;
                case "--tenant": options.Tenant = value; break;
                case "--scope": options.Scopes.Add(value); break;
                case "--login-hint": options.LoginHint = value; break;
                case "--home-account-id": options.HomeAccountId = value; break;
                default: throw new ArgumentException($"Unknown option '{args[index]}'. {Usage}");
            }
        }

        if (!Guid.TryParse(options.ClientId, out _) ||
            string.IsNullOrWhiteSpace(options.Tenant) ||
            (options.Mode != "--accounts" && options.Scopes.Count == 0) ||
            (options.LoginHint != null && options.HomeAccountId != null) ||
            (options.Mode == "--accounts" && (options.LoginHint != null || options.HomeAccountId != null)))
            throw new ArgumentException(Usage);

        return options;
    }

    private sealed class Options
    {
        public string Mode { get; set; } = "";
        public string ClientId { get; set; } = "";
        public string Tenant { get; set; } = "";
        public List<string> Scopes { get; } = new List<string>();
        public string? LoginHint { get; set; }
        public string? HomeAccountId { get; set; }
    }
}
