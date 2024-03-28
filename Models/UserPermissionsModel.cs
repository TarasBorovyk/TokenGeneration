namespace TokenGeneration.Models
{
    public sealed class UserPermissionsModel
    {
        public string UserId { get; set; }
        public IReadOnlyList<string> Permissions { get; set; }
    }
}
