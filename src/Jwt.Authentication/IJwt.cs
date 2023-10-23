using Orion.AspNetCore.JWTAuthentication.Models;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Orion.AspNetCore.JWTAuthentication;

/// <summary>
/// A generic class for the jwt token creation
/// </summary>
public interface IJwt
{
    /// <summary>
    /// Provides new jwt token based on credentials and claims for authentication
    /// </summary>
    /// <param name="username">HttpContext.User.Identity.Name</param>
    /// <param name="roles"></param>
    /// <returns></returns>
    string GetJwtToken(string username = null, List<Claim>? roles = null);

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    string CreateRefreshToken();
   
}

/// <summary>
/// A generic class for the jwt token creation
/// </summary>
public interface IJwt<T> where T : JwtOptions
{
    /// <summary>
    /// Provides new jwt token based on credentials and claims for authentication
    /// </summary>
    /// <param name="username">HttpContext.User.Identity.Name</param>
    /// <param name="action"></param>
    /// <param name="roles"></param>
    /// <returns></returns>
    string GetJwtToken(string username = null, List<Claim>? roles = null, Action<List<Claim>, T> claimList = null);

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    string CreateRefreshToken();
}
