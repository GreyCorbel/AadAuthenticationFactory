using Microsoft.Identity.Client;

namespace AadAuthenticationFactory
{
    public sealed class MacBrokerAccount : IAccount
    {
        public string Username { get; private set; }
        public string Environment { get; private set; }
        public AccountId HomeAccountId { get; private set; }

        public MacBrokerAccount(string username, string environment, string homeAccountId)
        {
            Username = username;
            Environment = environment;
            HomeAccountId = new AccountId(homeAccountId);
        }
    }
}
