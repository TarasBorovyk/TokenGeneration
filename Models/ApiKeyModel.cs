namespace TokenGeneration.Models
{
    public sealed class ApiKeyModel
    {
        public string ApiKey { get; set; }
        public IReadOnlyList<string> Permissions { get; set; }
    }
}
