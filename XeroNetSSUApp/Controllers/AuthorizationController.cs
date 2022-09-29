using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;
using Xero.NetStandard.OAuth2.Client;
using Xero.NetStandard.OAuth2.Config;
using Xero.NetStandard.OAuth2.Models;
using Xero.NetStandard.OAuth2.Token;
using XeroNetSSUApp.Models;

namespace XeroNetStandardApp.Controllers
{
  public class AuthorizationController : Controller
  {
    private readonly ILogger<AuthorizationController> _logger;
    private readonly IOptions<XeroConfiguration> XeroConfig;
    private readonly UserContext _context;
    
    // GET /Authorization/
    public AuthorizationController(IOptions<XeroConfiguration> XeroConfig, ILogger<AuthorizationController> logger, UserContext context)
    {
      _logger = logger;
      this.XeroConfig = XeroConfig;
      _context = context;
    }

    public IActionResult Index()
    {
      var client = new XeroClient(XeroConfig.Value);
      
      var clientState = Guid.NewGuid().ToString(); 
      TokenUtilities.StoreState(clientState);

      return Redirect(client.BuildLoginUri(clientState));
    }

    // GET /Authorization/Callback
    public async Task<ActionResult> Callback(string code, string state)
    {
      var clientState = TokenUtilities.GetCurrentState();

      if (state != clientState) {
        return Content("Cross site forgery attack detected!");
      }

      var client = new XeroClient(XeroConfig.Value);
      var xeroToken = (XeroOAuth2Token)await client.RequestAccessTokenAsync(code);

      if ((xeroToken.IdToken != null) && !JwtUtils.validateIdToken(xeroToken.IdToken, XeroConfig.Value.ClientId))
      {
        return Content("ID token is not valid");
      }

      if ((xeroToken.AccessToken != null) && !JwtUtils.validateAccessToken(xeroToken.AccessToken))
      {
        return Content("Access token is not valid");
      }

      TokenUtilities.StoreToken(xeroToken);

      // Sends user info from xero to register a new user
      User user = GetUserFromIdToken(xeroToken.IdToken);

      Register(user);
      return RedirectToAction("Index", "OrganisationInfo");
    }

    // GET /Authorization/Disconnect
    public async Task<ActionResult> Disconnect()
    {      
      var client = new XeroClient(XeroConfig.Value);

      var xeroToken = TokenUtilities.GetStoredToken();
      var utcTimeNow = DateTime.UtcNow;

      if (utcTimeNow > xeroToken.ExpiresAtUtc)
      {
        xeroToken = (XeroOAuth2Token)await client.RefreshAccessTokenAsync(xeroToken);
        TokenUtilities.StoreToken(xeroToken);
      }

      string accessToken = xeroToken.AccessToken;
      Tenant xeroTenant = xeroToken.Tenants.Find(tenant => tenant.TenantId == TokenUtilities.GetCurrentTenantId());

      await client.DeleteConnectionAsync(xeroToken, xeroTenant);

      // Update the xero token to exclude removed tenant
      xeroToken.Tenants.Remove(xeroTenant);
      TokenUtilities.StoreToken(xeroToken);

      User user = GetUserFromIdToken(xeroToken.IdToken);
      DeleteAccount(user);
      return RedirectToAction("Index", "Home");
    }

    //GET /Authorization/Revoke
    public async Task<ActionResult> Revoke()
    {      
      var client = new XeroClient(XeroConfig.Value);

      var xeroToken = TokenUtilities.GetStoredToken();
      var utcTimeNow = DateTime.UtcNow;

      if (utcTimeNow > xeroToken.ExpiresAtUtc)
      {
        xeroToken = (XeroOAuth2Token)await client.RefreshAccessTokenAsync(xeroToken);
        TokenUtilities.StoreToken(xeroToken);
      }

      await client.RevokeAccessTokenAsync(xeroToken);

      TokenUtilities.DestroyToken();

      return RedirectToAction("Index", "Home");
    }


    // Creates a user in the local database
    private void Register(User user)
    {
      _context.Database.EnsureCreated();

      if (_context.User.Find(user.XeroUserId) != null)
      {
        var existingUser = _context.Find<User>(user.XeroUserId);
        _context.Entry(existingUser).CurrentValues.SetValues(user);
        _context.Entry(existingUser).State = EntityState.Modified;
      }
      else
      {
        _context.Add<User>(user);
      }
      _context.SaveChanges();
    }

    // Delete account for user in the local database
    private void DeleteAccount(User user)
    {
      _context.Database.EnsureCreated();

      if (_context.User.Find(user.XeroUserId) != null)
      {
        var existingUser = _context.Find<User>(user.XeroUserId);
        _context.Entry(existingUser).State = EntityState.Deleted;
      }
      _context.SaveChanges();
    }

    private User GetUserFromIdToken(String IdToken)
    {
      var handler = new JwtSecurityTokenHandler();
      var token = handler.ReadJwtToken(IdToken);

      // Extract the information from token
      return new User
      {
        Email = token.Claims.First(claim => claim.Type == "email").Value,
        XeroUserId = token.Claims.First(claim => claim.Type == "xero_userid").Value,
        SessionId = token.Claims.First(claim => claim.Type == "global_session_id").Value,
        Name = token.Claims.First(claim => claim.Type == "name").Value,
        FirstName = token.Claims.First(claim => claim.Type == "given_name").Value,
        LastName = token.Claims.First(claim => claim.Type == "family_name").Value,
      };
    }
  }
}
