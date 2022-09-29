using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xero.NetStandard.OAuth2.Client;
using Xero.NetStandard.OAuth2.Api;
using Xero.NetStandard.OAuth2.Config;
using Xero.NetStandard.OAuth2.Token;
using Xero.NetStandard.OAuth2.Model.Accounting;
using XeroNetStandardApp.Models;
using System.Linq;

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
    public async Task<IActionResult> IndexAsync()
    {
      if (User.Identity.IsAuthenticated)
      {
        var xeroToken = TokenUtilities.GetStoredToken();
        var utcTimeNow = DateTime.UtcNow;

        if (utcTimeNow > xeroToken.ExpiresAtUtc)
        {
          var client = new XeroClient(XeroConfig.Value);
          xeroToken = (XeroOAuth2Token)await client.RefreshAccessTokenAsync(xeroToken);
          TokenUtilities.StoreToken(xeroToken);
        }

        string accessToken = xeroToken.AccessToken;
        Guid tenantId = TokenUtilities.GetCurrentTenantId();
        string xeroTenantId;
        if (xeroToken.Tenants.Any((t) => t.TenantId == tenantId))
        {
          xeroTenantId = tenantId.ToString();
        }
        else
        {
          var id = xeroToken.Tenants.First().TenantId;
          xeroTenantId = id.ToString();
          TokenUtilities.StoreTenantId(id);
        }

        var AccountingApi = new AccountingApi();
        var response = await AccountingApi.GetOrganisationsAsync(accessToken, xeroTenantId);
        var organisation_info = new Organisation();

        organisation_info = response._Organisations[0];
        ViewBag.jsonResponse = response.ToJson();

        return View(organisation_info);
      }

      return View();
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


