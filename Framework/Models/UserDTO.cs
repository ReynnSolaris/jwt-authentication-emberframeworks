namespace JWTAuthentication.Framework.Models
{
    public class UserDTO
    {
        public int Id { get; set; }
        public string UserName { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string PreferredName { get; set; }
        public string Password { get; set; }
        public string Salt { get; set; }
        public int RoleId { get; set; }
        public int JobId { get; set; }
        public Role Role { get; set; }


        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }

        public JobTitles JobTitles { get; set; }
        public ICollection<SystemAnnouncements> Announcements { get; set; }
        public ICollection<EmergencyContact> EmergencyContacts { get; set; }
        public Address CurrentAddress { get; set; }
        public PayInformation PayInformation { get; set; }
    }
}
