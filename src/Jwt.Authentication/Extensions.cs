using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
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
    /// <param name="builder"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    public static WebApplicationBuilder AddDefaultJwtService(this WebApplicationBuilder builder)
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection(JwtOptions.SectionName));

        builder.Services.AddScoped<IJwt, Jwt>();

        return builder;
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
    /// <param name="builder"></param>
    /// <param name="section">The section that defines the JWT parameters in appsetting.json</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public static WebApplicationBuilder AddGenericJwtService<T>(this WebApplicationBuilder builder, string section) where T : JwtOptions
    {
        if (builder is null)
        {
            throw new ArgumentNullException(nameof(builder));
        }

        if (string.IsNullOrEmpty(section))
        {
            throw new ArgumentException($"'{nameof(section)}' null veya boþ olamaz.", nameof(section));
        }

        builder.Services.Configure<T>(builder.Configuration.GetSection(section));

        builder.Services.AddScoped(typeof(IJwt<T>), typeof(Jwt<T>));

        return builder;
    }
}
