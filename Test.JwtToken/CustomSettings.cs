using Orion.AspNetCore.JWTAuthentication.Models;

namespace Test.JwtToken;

public class CustomSettings : JwtOptions
{
    public string Sample { get; set; }
}
