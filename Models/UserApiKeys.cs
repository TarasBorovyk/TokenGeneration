namespace TokenGeneration.Models
{
    public sealed class UserApiKeys
    {
        public string UserId { get; set; }
        public IList<ApiKeyModel> ApiKeys { get; set; } = new List<ApiKeyModel>();
    }
}
