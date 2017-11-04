using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace UmbracoHybrid
{
    public class ClaimsTransformer
    {
        public static async Task GenerateUserIdentityAsync(
            SecurityTokenValidatedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            var identityUser = new ClaimsIdentity(
                notification.AuthenticationTicket.Identity.Claims,
                notification.AuthenticationTicket.Identity.AuthenticationType,
                ClaimTypes.Name,
                ClaimTypes.Role);

            var newIdentityUser = new ClaimsIdentity(identityUser.AuthenticationType,
                ClaimTypes.GivenName, ClaimTypes.Role);

            newIdentityUser.AddClaim(identityUser.FindFirst(ClaimTypes.NameIdentifier));

            var emailClaim = identityUser.FindFirst(ClaimTypes.Email) ?? new Claim(ClaimTypes.Email, identityUser.FindFirst("name").Value);
            newIdentityUser.AddClaim(emailClaim);

            //Optionally add other claims
            var userInfoClient = new UserInfoClient(
                new Uri(notification.Options.Authority + "/connect/userinfo").ToString());

            var userInfo = await userInfoClient.GetAsync(notification.ProtocolMessage.AccessToken);
            newIdentityUser.AddClaims(userInfo.Claims.Select(t => new Claim(t.Type, t.Value)));

            notification.AuthenticationTicket = new AuthenticationTicket(newIdentityUser,
                notification.AuthenticationTicket.Properties);
        }
    }
}