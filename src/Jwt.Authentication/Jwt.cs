using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Orion.AspNetCore.JWTAuthentication.Models;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Orion.AspNetCore.JWTAuthentication;

/// <summary>
/// A generic class for the jwt token creation
/// </summary>
public class Jwt : IJwt
{
    private readonly JwtOptions jwtOptions;
    private readonly ILogger<Jwt> logger;

    /// <summary>
    /// Default Constructor
    /// </summary>
    /// <param name="logger"></param>
    /// <param name="jwtParams"></param>
    public Jwt(ILogger<Jwt> logger, IOptionsMonitor<JwtOptions> jwtParams)
    {
        if (jwtParams is null) ArgumentException.ThrowIfNullOrEmpty(nameof(jwtParams));

        jwtOptions = jwtParams.CurrentValue;

        this.logger = logger;
    }


    /// <summary>
    /// Provides new jwt token based on credentials and claims for authentication
    /// </summary>
    /// <param name="username">HttpContext.User.Identity.Name</param>
    /// <param name="roles"></param>
    /// <returns></returns>
    public string GetJwtToken(string username = null, List<Claim>? roles = null)
    {
        // Set tokens claims
        var claims = new List<Claim>
        {
                // Unique Id for this token
                new Claim(JwtRegisteredClaimNames.Jti , Guid.NewGuid().ToString("N",CultureInfo.CurrentCulture)),
                
                // Ability to not been used before the token was created.
                new Claim(JwtRegisteredClaimNames.Nbf, new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)),
        };

        if (username is not null)
            claims.Add(
                // The username using the identity name so it fills out the HttpContext.User.Identity.Name value
                new Claim(ClaimsIdentity.DefaultNameClaimType, username));

        // Check if additional claims exist
        if (roles is not null && roles.Any())
        {
            foreach (var role in roles)
            {
                // add new claims to jwt claims
                claims.Add(role);
            }
        }

        if (jwtOptions.Audience is not null && jwtOptions.Audience.Any())
            foreach (var aud in jwtOptions.Audience)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Aud, aud.ToString()));
            }

        var duration = jwtOptions.TokenLifeTime;

        var expire = jwtOptions.TokenLifeTimeFormat;

        // Create credentials for generating token
        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(
                // Get the secret key from configuration
                Encoding.UTF8.GetBytes(jwtOptions.Key)),
                // Use the HS256 algorithm
                SecurityAlgorithms.HmacSha256);

        // Generate jwt token
        var token = new JwtSecurityToken(
            issuer: jwtOptions.Issuer,
            audience: null,
            claims: claims,
            expires: expire.Contains("minutes", StringComparison.CurrentCultureIgnoreCase) ? DateTime.Now.AddMinutes(int.TryParse(duration, out var result) ? result : 15) : DateTime.Now.AddHours(int.TryParse(duration, out result) ? result : 24),
            signingCredentials: credentials);

        logger.LogInformation("Token created on {0}.", DateTime.Now.ToString());

        // Return new jwt token based on the credentials and claims
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

/// <summary>
/// A generic class for the jwt token creation
/// </summary>
public class Jwt<T> : IJwt<T> where T : JwtOptions
{
    private readonly T jwtOptions;
    private readonly ILogger<Jwt<T>> logger;

    /// <summary>
    /// Default Constructor
    /// </summary>
    /// <param name="logger"></param>
    /// <param name="jwtParams"></param>
    public Jwt(ILogger<Jwt<T>> logger, IOptionsMonitor<T> jwtParams)
    {
        if (jwtParams is null) ArgumentException.ThrowIfNullOrEmpty(nameof(jwtParams));

        jwtOptions = jwtParams.CurrentValue;

        this.logger = logger;
    }


    /// <summary>
    /// Provides new jwt token based on credentials and claims for authentication
    /// </summary>
    /// <param name="username">HttpContext.User.Identity.Name</param>
    /// <param name="action"></param>
    /// <param name="roles"></param>
    /// <returns></returns>
    public string GetJwtToken(string username = null, List<Claim>? roles = null, Action<List<Claim>, T> claimList = null)
    {
        // Set tokens claims
        var claims = new List<Claim>
        {
                // Unique Id for this token
                new Claim(JwtRegisteredClaimNames.Jti , Guid.NewGuid().ToString("N",CultureInfo.CurrentCulture)),

                // Ability to not been used before the token was created.
                new Claim(JwtRegisteredClaimNames.Nbf, new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)),

        };

        if (username is not null)
            claims.Add(
                // The username using the identity name so it fills out the HttpContext.User.Identity.Name value
                new Claim(ClaimsIdentity.DefaultNameClaimType, username));

        // Check if additional claims exist
        if (roles is not null && roles.Any())
        {
            foreach (var role in roles)
            {
                // add new claims to jwt claims
                claims.Add(role);
            }
        }

        if (jwtOptions.Audience is not null && jwtOptions.Audience.Any())
            foreach (var aud in jwtOptions.Audience)
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Aud, aud.ToString()));
            }

        var duration = jwtOptions.TokenLifeTime;

        var expire = jwtOptions.TokenLifeTimeFormat;

        // Create credentials for generating token
        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(
                // Get the secret key from configuration
                Encoding.UTF8.GetBytes(jwtOptions.Key)),
                // Use the HS256 algorithm
                SecurityAlgorithms.HmacSha256);

        if (claimList is not null)
            claimList.Invoke(claims, jwtOptions);

        // Generate jwt token
        var token = new JwtSecurityToken(
            issuer: jwtOptions.Issuer,
            audience: null,
            claims: claims,
            expires: expire.Contains("minutes", StringComparison.CurrentCultureIgnoreCase) ? DateTime.Now.AddMinutes(int.TryParse(duration, out var result) ? result : 15) : DateTime.Now.AddHours(int.TryParse(duration, out result) ? result : 24),
            signingCredentials: credentials);


        logger.LogInformation("Token created on {}.", DateTime.Now.ToString());

        // Return new jwt token based on the credentials and claims
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
