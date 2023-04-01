namespace GreyCorbel.Identity.Authentication
{
    internal class ManagedIdentityAuthenticationResponse
    {
        public string access_token { get; set; }
        //on Arc server only
        public string refresh_token { get; set; }
        //not present on Arc
        public string client_id { get; set; }
        public string expires_in { get; set; }
        public string ext_expires_in { get; set; }
        public string expires_on { get; set; }
        public string not_before { get; set; }
        public string resource { get; set; }
        public string token_type { get; set; }
    }
}
