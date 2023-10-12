namespace Orion.AspNetCore.JWTAuthentication.Models;


public class JwtOptions 
{
    internal const string SectionName = "Jwt";

    public JwtOptions()
    {
        
    }

    public string Issuer { get; set; }

    public string[] Audience { get; set; }

    public string TokenLifeTimeFormat { get; set; }

    public string TokenLifeTime { get; set; }

    public string Key { get; set; }

}
