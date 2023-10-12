using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Orion.AspNetCore.JWTAuthentication.Models;

namespace Orion.AspNetCore.JWTAuthentication.Extensions;

/// <summary>
/// 
/// </summary>
public static class Extensions
{

    /// <summary>
    /// <para>
    /// JWT SECTION in appsettings.json file
    /// <code>
    /// "Jwt": {
    ///     "Key": "YourSecretKey",
    ///     "Issuer": "Your-Service",
    ///     "Audience": [
    ///     "aud1","aud2","aud3",...],
    ///     "TokenLifeTimeFormat": "minutes" or "hours",
    ///     "TokenLifeTime": "15" }
    /// </code>
    /// </para>
    /// <para>
    /// Adds a service for the JWT token provider with option class <see cref="JwtOptions"/>
    /// </para>
    /// </summary>
    /// <param name="services"></param>
    /// <param name="configuration"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    public static IServiceCollection AddDefaultJwtService(this IServiceCollection services, IConfiguration configuration)
    {
        if (services is null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.Configure<JwtOptions>(configuration.GetSection(JwtOptions.SectionName));

        services.AddScoped<IJwt>(sp =>
        {
            var logger = sp.GetRequiredService<ILogger<Jwt>>();

            var options = sp.GetRequiredService<IOptionsMonitor<JwtOptions>>();

            logger.LogInformation("Adding services {0} to collection. ", nameof(IJwt));

            return new Jwt(logger, options);
        });

        return services;
    }

    /// <summary>
    /// <para>
    /// JWT SECTION in appsettings.json file
    /// <code>
    /// "Jwt": {
    ///     "Key": "YourSecretKey",
    ///     "Issuer": "Your-Services
    ///     "Audience": [
    ///     "aud1","aud2","aud3",...],
    ///     "TokenLifeTimeFormat": "minutes" or "hours",
    ///     "TokenLifeTime": "15" }
    /// </code>
    /// </para>
    /// <para>
    /// Adds generic service for the JWT token provider with custom option class based on <see cref="JwtOptions"/>
    /// </para>
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="services"></param>
    /// <param name="configuration"></param>
    /// <param name="section">The section that defines the JWT parameters in appsetting.json</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public static IServiceCollection AddGenericJwtService<T>(this IServiceCollection services, IConfiguration configuration, string section) where T : JwtOptions
    {
        if (services is null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        if (string.IsNullOrEmpty(section))
        {
            throw new ArgumentException($"'{nameof(section)}' null veya boþ olamaz.", nameof(section));
        }

        services.Configure<T>(configuration.GetSection(section));

        services.AddScoped(typeof(IJwt<T>), sp =>
        {
            var logger = sp.GetRequiredService<ILogger<Jwt<T>>>();

            var options = sp.GetRequiredService<IOptionsMonitor<T>>();

            logger.LogInformation("Adding services {0} to collection. ", nameof(IJwt<T>));

            return new Jwt<T>(logger, options);
        });

        return services;
    }
}
