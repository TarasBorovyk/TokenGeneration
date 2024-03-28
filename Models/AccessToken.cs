namespace TokenGeneration.Models
{
    public sealed class AccessToken
    {
        public string Token { get; set; }
        public DateTime? LastUsedAt { get; set; }
        public bool IsActive { get; set; }
    }
}
