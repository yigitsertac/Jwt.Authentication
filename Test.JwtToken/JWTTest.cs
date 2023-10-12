using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Orion.AspNetCore.JWTAuthentication;
using Orion.AspNetCore.JWTAuthentication.Extensions;
using Orion.AspNetCore.JWTAuthentication.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;

namespace Test.JwtToken;

[TestClass]
public class JWTTest
{
    private readonly ServiceCollection services;

    public JWTTest()
    {
        services = new();

        services.AddLogging(config => config.AddConsole());

        services.AddGenericJwtService<CustomSettings>(GetConfiguration(), "Jwt");
    }


    [TestMethod]
    public void TokenGenerationTest()
    {
        var sp = services.BuildServiceProvider();
        var tokenGenerator = sp.GetRequiredService<IJwt>();

        var token = tokenGenerator.GetJwtToken("yigitsertac");

        Console.WriteLine(token);
    }

    [TestMethod]
    public void TokenGenericGenerationTest()
    {
        var sp = services.BuildServiceProvider();
        var tokenGenerator = sp.GetRequiredService(typeof(IJwt<CustomSettings>)) as IJwt<CustomSettings>;

        var token = tokenGenerator.GetJwtToken(claimList:(claimList,options) =>
        {
            claimList.Add(new Claim(JwtRegisteredClaimNames.Birthdate, options.Sample));
        });

        Console.WriteLine(token);
    }


    private static IConfiguration GetConfiguration()
    {
        var config = new ConfigurationBuilder()
            .SetBasePath(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location))
            .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true).Build();

        return config;

    }
}