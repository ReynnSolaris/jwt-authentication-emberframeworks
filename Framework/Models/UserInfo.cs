namespace JWTAuthentication.Framework.Models
{
    public class UserInfo
    {
        public int UserId { get; set; }
        public string UserName { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string PreferredName { get; set; }
        public string RoleName { get; set; }
        public string Address { get; set; }
        public List<EmergencyContactDTO> EmergencyContacts { get; set; }
        public string JobTitle { get; set; }
        public List<string> Permissions { get; set; }
        public decimal? HourlyRate { get; set; }
        public decimal? SalaryRate { get; set; }
        public string PositionType { get; set; }
        public List<SystemAnnouncementDTO> Announcements { get; set; } 

    }
}