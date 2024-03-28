using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using TokenGeneration.Models;

namespace TokenGeneration.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccessController : ControllerBase
    {
        // Move to respective repository and perform logic business logic in services
        private static readonly List<UserApiKeys> userApiKeys = new();
        private static readonly List<ApiKeyModel> apiKeys = new();
        private static readonly List<AccessToken> accessTokens = new();
        private static readonly List<ApiKeyAccessTokens> apiKeyAccessTokens = new();

        // Move to appSettings and inject with IOptions<T>
        private readonly string secretKey = "dnVsNzQzbDNyem8yems4cHF0dmJ5cWM2amx5NncyOHhqMG9iMnk3czV1b2szeW9ndTRzbmxia2I5ajg1YWRzd2MwNmpoeW91M3FrdzZ2NW9yZHFyZXV6ZmUycXdkeWNrMWplOHU5eHdjdTdrbTl0dnJpNDY1aXpxc2pnNm1iMHk=\r\n";
        private readonly string issuer = "issuer";
        private readonly string audience = "audience";

        [HttpPost("Create")]
        public ActionResult<string> CreateApiKey()
        {
            UserPermissionsModel userPermissions = AuthenticateRequest(Request);
            if (userPermissions == null)
                return Unauthorized();

            UserApiKeys userApiKey = userApiKeys.FirstOrDefault(u => u.UserId == userPermissions.UserId);
            if(userApiKey == null)
            {
                userApiKey = new UserApiKeys()
                {
                    UserId = userPermissions.UserId
                };

                userApiKeys.Add(userApiKey);
            }

            string apiKey = Guid.NewGuid().ToString(); // Add checking if already exists
            var apiKeyModel = new ApiKeyModel()
            {
                ApiKey = apiKey,
                Permissions = userPermissions.Permissions
            };

            apiKeys.Add(apiKeyModel);
            userApiKey.ApiKeys.Add(apiKeyModel);
            
            return apiKey;
        }

        [HttpPost("Authenticate")]
        public ActionResult<string> Authenticate([FromBody] ApiKeyRequest request)
        {
            UserApiKeys userApiKey = userApiKeys
                .Where(u => u.ApiKeys.Any(k => k.ApiKey == request.ApiKey))
                .FirstOrDefault();

            if(userApiKey == null)
                return NotFound("API Key not found");

            ApiKeyModel apiKey = userApiKey.ApiKeys
                .FirstOrDefault(k => k.ApiKey == request.ApiKey);

            var token = GenerateToken(userApiKey.UserId, apiKey.Permissions.ToArray());
            accessTokens.Add(token);
            ApiKeyAccessTokens apiKeyAccessToken = apiKeyAccessTokens.FirstOrDefault(k => k.ApiKey == request.ApiKey);
            if(apiKeyAccessToken == null)
            {
                apiKeyAccessToken = new ApiKeyAccessTokens()
                {
                    ApiKey = request.ApiKey
                };

                apiKeyAccessTokens.Add(apiKeyAccessToken);
            }

            apiKeyAccessToken.AccessTokens.Add(token);

            return token.Token;
        }

        [HttpDelete("Revoke")]
        public IActionResult RevokeApiKey(AccessTokenRequest accessTokenRequest)
        {
            UserPermissionsModel userPermissions = AuthenticateRequest(Request);
            if (userPermissions == null)
                return Unauthorized();

            AccessToken accessToken = accessTokens.FirstOrDefault(t => t.Token == accessTokenRequest.AccessToken);
            if (accessToken == null || !accessToken.IsActive) // + Decode token and check expiration
                return Unauthorized();

            ApiKeyAccessTokens apiKeyAccessToken = apiKeyAccessTokens
                .FirstOrDefault(x => x.AccessTokens.Any(a => a.Token == accessTokenRequest.AccessToken));
            ApiKeyModel apiKeyToRevoke = apiKeys.FirstOrDefault(x => x.ApiKey == apiKeyAccessToken.ApiKey);
            apiKeys.Remove(apiKeyToRevoke);

            return Ok();
        }

        [HttpGet]
        public ActionResult<IEnumerable<AccessToken>> GetTokens()
        {
            UserPermissionsModel userPermissions = AuthenticateRequest(Request);
            if (userPermissions == null)
                return Unauthorized();

            List<ApiKeyModel> userApiKey = userApiKeys
                .Where(x => x.UserId == userPermissions.UserId)
                .SelectMany(x => x.ApiKeys)
                .ToList();

            List<string> apiKeys = userApiKey.Select(x => x.ApiKey).ToList();
            List<AccessToken> accessToken = apiKeyAccessTokens
                .Where(x => apiKeys.Contains(x.ApiKey))
                .SelectMany(x => x.AccessTokens) 
                .ToList();

            return accessToken;
        }

        // Simulated authentication function (replace with actual implementation)
        private UserPermissionsModel AuthenticateRequest(HttpRequest request)
        {
            return new UserPermissionsModel()
            {
                UserId = $"user_228",
                Permissions = new List<string>()
                {
                    "read_customers",
                    "write_customers"
                }
            };
        }

        private AccessToken GenerateToken(string userId, string[] permissions)
        {
            var claims = new[]
            {
                new Claim("name", userId),
                new Claim("permissions", string.Join('|', permissions))
            };

            var key = new SymmetricSecurityKey(Convert.FromBase64String(secretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            AccessToken accessToken = new()
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                LastUsedAt = DateTime.UtcNow,
                IsActive = true
            };

            return accessToken;
        }
    }
}
