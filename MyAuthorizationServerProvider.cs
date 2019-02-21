using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using TokenBasedAuthentication2.Models;

namespace TokenBasedAuthentication2
{
	public class MyAuthorizationServerProvider : OAuthAuthorizationServerProvider
	{

		SampleEntities db = new SampleEntities();
		public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
		{
			context.Validated(); // 
		}

		public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context )
		{
			
			var result = (from a in db.Users
						  where a.UserName.Equals(context.UserName) &&
						  a.Password.Equals(context.Password)
						  select new
						  {
							  a.UserName,
							  a.Password,
							  a.Name
						  }).ToList();

			if(result.Count()>0)
			{
				for (int i = 0; i < result.Count(); i++)
				{
					var identity = new ClaimsIdentity(context.Options.AuthenticationType);
					
					if (context.UserName == result.ToList()[i].UserName  && context.Password ==result.ToList()[i].Password)
					{
						identity.AddClaim(new Claim(ClaimTypes.Role, result.ToList()[i].UserName));
						identity.AddClaim(new Claim("username", result.ToList()[i].Password));
						identity.AddClaim(new Claim(ClaimTypes.Name,result.ToList()[i].Name));
						context.Validated(identity);
					}
				}
			}
			else
			{
				context.SetError("invalid_grant", "Provided username and password is incorrect");
				return;
			}
		}
	}
}
