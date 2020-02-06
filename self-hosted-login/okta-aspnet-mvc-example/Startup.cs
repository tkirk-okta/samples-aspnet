using System.Collections.Generic;
using System.Configuration;
using System.Threading.Tasks;
using System.Web;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Okta.AspNet;
using Owin;

[assembly: OwinStartup(typeof(okta_aspnet_mvc_example.Startup))]

namespace okta_aspnet_mvc_example
{
    public class Startup
    {
        private readonly ConfigurationManager<OpenIdConnectConfiguration> _configurationManager;

        public void Configuration(IAppBuilder app)
        {
           IdentityModelEventSource.ShowPII = true;
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions()
            {
                LoginPath = new PathString("/Account/Login"),
            });

            //app.UseOktaMvc(new OktaMvcOptions()
            //{
            //    OktaDomain = ConfigurationManager.AppSettings["okta:OktaDomain"],
            //    AuthorizationServerId = ConfigurationManager.AppSettings["okta:AuthorizationServerId"],
            //    ClientId = ConfigurationManager.AppSettings["okta:ClientId"],
            //    ClientSecret = ConfigurationManager.AppSettings["okta:ClientSecret"],
            //    RedirectUri = ConfigurationManager.AppSettings["okta:RedirectUri"],
            //    PostLogoutRedirectUri = ConfigurationManager.AppSettings["okta:PostLogoutRedirectUri"],
            //    Scope = new List<string> { "openid", "profile", "email" },
            //    LoginMode = LoginMode.SelfHosted,
            //    ResponseType = "code"
            //});
            app.UseOpenIdConnectAuthentication(new Microsoft.Owin.Security.OpenIdConnect.OpenIdConnectAuthenticationOptions()
            {
                ClientId = ConfigurationManager.AppSettings["okta:ClientId"],
                ClientSecret = ConfigurationManager.AppSettings["okta:ClientSecret"],
                Authority = ConfigurationManager.AppSettings["okta:OktaDomain"] +"/oauth2/" + ConfigurationManager.AppSettings["okta:AuthorizationServerId"],
                RedirectUri = ConfigurationManager.AppSettings["okta:RedirectUri"],
                PostLogoutRedirectUri = ConfigurationManager.AppSettings["okta:PostLogoutRedirectUri"],
                Scope = "openid profile email",
                ResponseType = "code",
                ResponseMode = "query",
                // https://github.com/IdentityServer/IdentityServer4.Demo/blob/master/src/IdentityServer4Demo/Config.cs
                //ClientId = "server.hybrid",
                //ClientSecret = "secret", // for code flow
                //Authority = "https://demo.identityserver.io/",
                /*
                Authority = Environment.GetEnvironmentVariable("oidc:authority"),
                ClientId = Environment.GetEnvironmentVariable("oidc:clientid"),
                RedirectUri = "https://localhost:44318/",
                ClientSecret = Environment.GetEnvironmentVariable("oidc:clientsecret"),*/
                // CookieManager = new SystemWebCookieManager(),
                //CookieManager = new SameSiteCookieManager(),
                //ResponseType = "code",
                //ResponseMode = "query",
                //SaveTokens = true,
                //Scope = "openid profile offline_access",
                //RedeemCode = true,
                TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    NameClaimType = "name"
                },
                Notifications = new Microsoft.Owin.Security.OpenIdConnect.OpenIdConnectAuthenticationNotifications
                {

                    RedirectToIdentityProvider = BeforeRedirectToIdentityProviderAsync,
                    AuthorizationCodeReceived = async n =>
                    {
                        var _configuration = await n.Options.ConfigurationManager.GetConfigurationAsync(n.OwinContext.Request.CallCancelled);
                        var requestMessage = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Post, _configuration.TokenEndpoint);

                        //
                        requestMessage.Content = new System.Net.Http.FormUrlEncodedContent(n.TokenEndpointRequest.Parameters);
                        var responseMessage = await n.Options.Backchannel.SendAsync(requestMessage);
                        responseMessage.EnsureSuccessStatusCode();
                        var responseContent = await responseMessage.Content.ReadAsStringAsync();
                        Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectMessage message = new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectMessage(responseContent);

                        n.HandleCodeRedemption(message);
                    }
                }
            });
            
        }
        private static Task BeforeRedirectToIdentityProviderAsync(RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> redirectToIdentityProviderNotification)
        {
            // If signing out, add the id_token_hint
            if (redirectToIdentityProviderNotification.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
            {
                if (redirectToIdentityProviderNotification.OwinContext.Authentication.User.FindFirst("id_token") != null)
                {
                    redirectToIdentityProviderNotification.ProtocolMessage.IdTokenHint = redirectToIdentityProviderNotification.OwinContext.Authentication.User.FindFirst("id_token").Value;
                }
            }

            // Add sessionToken to provide custom login
            if (redirectToIdentityProviderNotification.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
            {
                var sessionToken = string.Empty;
                redirectToIdentityProviderNotification.OwinContext.Authentication.AuthenticationResponseChallenge?.Properties?.Dictionary?.TryGetValue("sessionToken", out sessionToken);

                if (!string.IsNullOrEmpty(sessionToken))
                {
                    redirectToIdentityProviderNotification.ProtocolMessage.SetParameter("sessionToken", sessionToken);
                }

                var idpId = string.Empty;
                redirectToIdentityProviderNotification.OwinContext.Authentication.AuthenticationResponseChallenge?.Properties?.Dictionary?.TryGetValue("idp", out idpId);

                if (!string.IsNullOrEmpty(idpId))
                {
                    redirectToIdentityProviderNotification.ProtocolMessage.SetParameter("idp", idpId);
                }
            }

            return Task.FromResult(false);
        }
    }
}
