using System;
using System.Web.Configuration;

namespace MvcHybridOwin
{
    public static class Constants
    {
        public static string AuthenticationTypeCookies = "Cookies";
        public const string BearerAuthenticationType = "Bearer";
        public const string AccessTokenType = "access_token";
        public const string IdTokenType = "id_token";

        public static class ClientCredentials
        {
            public static readonly string ClientId = WebConfigurationManager.AppSettings["ClientId"];
            public static readonly string ClientSecret = WebConfigurationManager.AppSettings["ClientSecret"];
        }

        public static class Endpoints
        {
            public static readonly string IdentityServerEndpoint = WebConfigurationManager.AppSettings["IdentityServer.Endpoint"];          
            public static readonly Uri UserInfoEndpoint = new Uri($"{IdentityServerEndpoint}connect/userinfo");
            public static readonly string TokenEndpoint = $"{IdentityServerEndpoint}connect/token";
            public static readonly string ImisProxyEndpoint = IdentityServerEndpoint.Replace("identity", "proxy");
        }

        public static class OpenIdConnectSettings
        {
            public static readonly string[] ResponseTypes =
            {
            "code",
            "id_token",
            "token"
            
            };

            public static readonly string[] ScopesRequesting =
            {
                "openid",
                "offline_access",                
                "imisapi"
            };

            public static class ClaimTypeNames
            {
                public static readonly string AccessToken = "access_token";
                public static readonly string ExpiresAt = "expires_at";
                public static readonly string RefreshToken = "refresh_token";
                public static readonly string IdToken = "id_token";
                public static readonly string Subject = "sub";
            }

            public static class CustomClaimTypeNames
            {
                public static readonly string InstanceId = "InstanceId";
            }
        }
    }
}