using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Orion.AspNetCore.JWTAuthentication.Models;

namespace Orion.AspNetCore.JWTAuthentication.Factory;

/// <summary>
/// 
/// </summary>
public class JwtTokenGenerator
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="serviceProvider"></param>
    /// <returns></returns>
    public static IJwt Create(IServiceProvider serviceProvider)
    {
        var logger = serviceProvider.GetRequiredService<ILogger<Jwt>>();
        var options = serviceProvider.GetRequiredService<IOptionsMonitor<JwtOptions>>();

        return new Jwt(logger, options);
    }
}
