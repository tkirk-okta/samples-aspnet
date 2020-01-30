using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Okta.AspNet;
using Okta.Auth.Sdk;
using Okta.Sdk.Abstractions;
using Okta.Sdk.Abstractions.Configuration;
using okta_aspnet_mvc_example.Models;
using System.Configuration;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace okta_aspnet_mvc_example.Controllers
{
    public class AccountController : Controller
    {
        //[HttpPost]
        //[ValidateAntiForgeryToken]
        //public ActionResult Login(FormCollection form)
        //{
        //    if (!HttpContext.User.Identity.IsAuthenticated)
        //    {
        //        var properties = new AuthenticationProperties();
        //        properties.Dictionary.Add("sessionToken", form.Get("sessionToken"));
        //        properties.RedirectUri = "/Home/About";

        //        HttpContext.GetOwinContext().Authentication.Challenge(properties,
        //            OktaDefaults.MvcAuthenticationType);

        //        return new HttpUnauthorizedResult();
        //    }

        //    return RedirectToAction("Index", "Home");

        //}

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> LoginAsync(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View("Login");
            }

            var authnOptions = new AuthenticateOptions()
            {
                Username = model.UserName,
                Password = model.Password,
            };

            try
            {
                var _oktaAuthenticationClient = new AuthenticationClient(new OktaClientConfiguration
                {
                    OktaDomain = ConfigurationManager.AppSettings["okta:OktaDomain"],
                    Token = ConfigurationManager.AppSettings["okta:Token"],
                });
                var authnResponse = await _oktaAuthenticationClient.AuthenticateAsync(authnOptions).ConfigureAwait(false);

                if (authnResponse.AuthenticationStatus == AuthenticationStatus.Success)
                {
                    //var identity = new ClaimsIdentity(
                    //    new[] { new Claim(ClaimTypes.Name, model.UserName) },
                    //    DefaultAuthenticationTypes.ApplicationCookie);

                    //_authenticationManager.SignIn(new AuthenticationProperties { IsPersistent = model.RememberMe }, identity);

                    //return RedirectToAction("Index", "Home");
                    var properties = new AuthenticationProperties();
                    properties.Dictionary.Add("sessionToken", authnResponse.SessionToken);
                    properties.RedirectUri = "/Home/About";

                    HttpContext.GetOwinContext().Authentication.Challenge(properties,
                        Okta.AspNet.OktaDefaults.MvcAuthenticationType);

                    return new HttpUnauthorizedResult();

                }
                else if (authnResponse.AuthenticationStatus == AuthenticationStatus.PasswordExpired)
                {
                    Session["stateToken"] = authnResponse.StateToken;

                    return RedirectToAction("ChangePassword", "Manage");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, $"Invalid login attempt: {authnResponse.AuthenticationStatus}");
                    return View("Login", model);
                }
            }
            catch (OktaApiException exception)
            {
                ModelState.AddModelError(string.Empty, $"Invalid login attempt: {exception.ErrorSummary}");
                return View("Login", model);
            }
        }

        // GET: Account
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        [HttpPost]
        public ActionResult Logout()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                HttpContext.GetOwinContext().Authentication.SignOut(
                    CookieAuthenticationDefaults.AuthenticationType,
                    Okta.AspNet.OktaDefaults.MvcAuthenticationType);
            }

            return RedirectToAction("Index", "Home");
        }

        public ActionResult PostLogout()
        {
            return RedirectToAction("Index", "Home");
        }
    }
}