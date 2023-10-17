using System.Security.Cryptography;

namespace Orion.AspNetCore.JWTAuthentication.Base;

/// <summary>
/// 
/// </summary>
public class BaseJwt
{
    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    public string CreateRefreshToken()
    {
        var bytes = new byte[32];
        
        using var rnd = RandomNumberGenerator.Create();
        
        rnd.GetBytes(bytes);

        return Convert.ToBase64String(bytes);
        
    }
}
