namespace Orion.AspNetCore.JWTAuthentication.Models;


public abstract class JwtOptions 
{
    internal const string SectionName = "Jwt";

    internal string Issuer { get; set; }

    internal string[] Audience { get; set; }

    internal string TokenLifeTimeFormat { get; set; }

    internal string TokenLifeTime { get; set; }

    internal string Key { get; set; }

}
