﻿using Xero.NetStandard.OAuth2.Models;
using Xero.NetStandard.OAuth2.Token;

namespace XeroNetSSUApp.Utilities
{
  public class StateContainer
  {
    public Tenant CurrentTenant { get; set; }

    public XeroOAuth2Token XeroToken { get; set; }
  }
}
