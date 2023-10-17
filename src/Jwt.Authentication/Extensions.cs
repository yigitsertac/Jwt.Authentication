using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Orion.AspNetCore.JWTAuthentication.Models;
using System.Text;
using System.Text.Json;

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
    /// <para>
    /// Anywhere in the application call <see cref="IJwt"/>
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

            logger.LogInformation("Adding services {IJwt} to collection. ", nameof(IJwt));

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
    /// <para>
    /// Anywhere in the application call <see cref="IJwt{T}"/>
    /// </para>
    /// </summary>
    /// <typeparam name="T">A class for the options in appsettings.</typeparam>
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

    /// <summary>
    /// Adds the jwt bearer token authentication with jwt bearer configurations
    /// </summary>
    /// <param name="services"></param>
    /// <param name="configuration"></param>
    /// <returns></returns>
    public static IServiceCollection AddJwtAuthRegister(this IServiceCollection services, IConfiguration configuration)
    {
        
        services.AddAuthentication(options =>
        {
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearerConfiguration(configuration);

        return services;
    }

    /// <summary>
    /// Adds the jwt bearer token configuration
    /// </summary>
    /// <param name="builder"></param>
    /// <param name="configuration"></param>
    /// <returns></returns>
    private static AuthenticationBuilder AddJwtBearerConfiguration(this AuthenticationBuilder builder, IConfiguration configuration)
    {
        JwtOptions jwtOptions = new();

        configuration.GetSection(JwtOptions.SectionName).Bind(jwtOptions);

        return builder.AddJwtBearer(options =>
        {
            options.Audience = string.Join(string.Empty, jwtOptions.Audience);

            options.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ClockSkew = new TimeSpan(0, 0, 30),
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,

                ValidIssuer = jwtOptions.Issuer,
                ValidAudiences = jwtOptions.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Key))
            };

            options.Events = new JwtBearerEvents()
            {
                OnChallenge = context =>
                {
                    context.HandleResponse();

                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;

                    context.Response.ContentType = "application/json";

                    // Ensure we always have an error and error description.
                    if (string.IsNullOrEmpty(context.Error))
                        context.Error = "Invalid Token";

                    if (string.IsNullOrEmpty(context.ErrorDescription))
                        context.ErrorDescription = "This request requires a valid JWT access token to be provided";

                    // Add some extra context for expired tokens.
                    if (context.AuthenticateFailure != null && context.AuthenticateFailure.GetType() == typeof(SecurityTokenExpiredException))
                    {
                        var authenticationException = context.AuthenticateFailure as SecurityTokenExpiredException;

                        context.Response.Headers.Add("x-token-expired", $"{authenticationException.Expires:o}");

                        context.ErrorDescription = $"The token expired on {authenticationException.Expires:o}";
                    }

                    return context.Response.WriteAsync(JsonSerializer.Serialize(new
                    {
                        error = context.Error,
                        error_description = context.ErrorDescription
                    }));
                }
            };
        });
    }
}
