namespace TokenGeneration.Models
{
    public sealed class ApiKeyAccessTokens
    {
        public string ApiKey { get; set; }
        public IList<AccessToken> AccessTokens { get; set; } = new List<AccessToken>();
    }
}
