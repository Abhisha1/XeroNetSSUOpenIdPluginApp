using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using Xero.NetStandard.OAuth2.Api;
using Xero.NetStandard.OAuth2.Client;
using Xero.NetStandard.OAuth2.Config;
using Xero.NetStandard.OAuth2.Token;
using XeroNetSSUApp.Models;
using XeroNetStandardApp.Models;

namespace XeroNetStandardApp.Controllers
{
  public class HomeController : Controller
  {
    private readonly ILogger<HomeController> _logger;
    private readonly IOptions<XeroConfiguration> XeroConfig;

    public HomeController(IOptions<XeroConfiguration> XeroConfig, ILogger<HomeController> logger)
    {
      _logger = logger;
      this.XeroConfig = XeroConfig;
    } 
    public async Task<IActionResult> IndexAsync([FromQuery] Guid? tenantId)
    {
      if (User.Identity.IsAuthenticated)
      {
        var client = new XeroClient(XeroConfig.Value);

        var handler = new JwtSecurityTokenHandler();
        var accessToken = await HttpContext.GetTokenAsync("access_token");
        var accessTokenParsed = handler.ReadJwtToken(await HttpContext.GetTokenAsync("access_token"));
        var xeroToken = new XeroOAuth2Token()
        {
          AccessToken = accessToken,
          IdToken = await HttpContext.GetTokenAsync("id_token"),
          ExpiresAtUtc = accessTokenParsed.ValidTo,
          RefreshToken = await HttpContext.GetTokenAsync("refresh_token"),
        };

        xeroToken.Tenants = await client.GetConnectionsAsync(xeroToken);

        if (DateTime.UtcNow > xeroToken.ExpiresAtUtc)
        {
          xeroToken = await updateToken(xeroToken);
        }
        if (tenantId is Guid tenantIdValue)
        {
          TokenUtilities.StoreTenantId(tenantIdValue);
        } else
        {
          tenantIdValue = TokenUtilities.GetCurrentTenantId();
        }
        string xeroTenantId;
        if (xeroToken.Tenants.Any((t) => t.TenantId == tenantIdValue))
        {
          xeroTenantId = tenantIdValue.ToString();
        }
        else
        {
          var id = xeroToken.Tenants.First().TenantId;
          xeroTenantId = id.ToString();
          TokenUtilities.StoreTenantId(id);
        }

        // Make calls to Xero requesting organisation info, accounts and contacts and feed into dashboard
        var AccountingApi = new AccountingApi();
        try
        {
          var organisation_info = await AccountingApi.GetOrganisationsAsync(accessToken, xeroTenantId);

          var contacts = await AccountingApi.GetContactsAsync(accessToken, xeroTenantId);

          var accounts = await AccountingApi.GetAccountsAsync(accessToken, xeroTenantId);

          
          var response = new DashboardModel { accounts = accounts, contacts = contacts, organisation = organisation_info };

          return View(response);
        } catch (ApiException e)
        {
          // If the current tenant is disconnected from the app, redirect to re-authorize
          if (e.ErrorCode == 403)
          {
            return RedirectToAction("Index", "Authorization");
          }
        }
          
      }

      return View();
    }

    // Refreshes token and updates local token to contain updated version
    private async Task<XeroOAuth2Token> updateToken(XeroOAuth2Token xeroToken) 
    {
      var client = new XeroClient(XeroConfig.Value);
      xeroToken = (XeroOAuth2Token)await client.RefreshAccessTokenAsync(xeroToken);
      TokenUtilities.StoreToken(xeroToken);
      return xeroToken;
    }
    [HttpGet]
    [Authorize]
    public IActionResult NoTenants()
    {
      return View();
    }

    [HttpGet]
    [Authorize(AuthenticationSchemes = "XeroSignUp")]
    public IActionResult SignUp()
    {
      return RedirectToAction("Index");
    }

    [HttpGet]
    [Authorize(AuthenticationSchemes = "XeroSignIn")]
    public IActionResult SignIn()
    {
      return RedirectToAction("Index");
    }

    public IActionResult Privacy()
    {
      return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
      return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
  }
}


