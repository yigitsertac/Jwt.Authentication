using Microsoft.IdentityModel.Tokens;
using Orion.AspNetCore.JWTAuthentication.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

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
    string GetJwtToken(string username, List<Claim>? roles = null);
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
    string GetJwtToken(string username, Action<JwtSecurityToken> action, List<Claim>? roles = null);
}
