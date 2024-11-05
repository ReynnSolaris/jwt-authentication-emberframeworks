using JWTAuthentication.Framework.Models;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthentication.Framework.Database
{
    public class ApplicationDbContext : DbContext
    {
        public DbSet<UserDTO> Users { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<Permission> Permissions { get; set; }
        public DbSet<RolePermission> RolePermissions { get; set; }
        public DbSet<RoleHierarchy> RoleHierarchy { get; set; }
        public DbSet<UserPermission> UserPermissions { get; set; }
        public DbSet<SystemAnnouncements> System_Announcements { get; set; }
        public DbSet<PayInformation> PayInformation { get; set; }
        public DbSet<JobTitles> Job_Titles { get; set; }
        public DbSet<Address> Addresses { get; set; }
        public DbSet<EmergencyContact> EmergencyContacts { get; set; }
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Role>()
                .HasMany(r => r.RolePermissions)
                .WithOne(rp => rp.Role)
                .HasForeignKey(rp => rp.RoleId);

            modelBuilder.Entity<Permission>()
                .HasMany(p => p.RolePermissions)
                .WithOne(rp => rp.Permission)
                .HasForeignKey(rp => rp.PermissionId);

            modelBuilder.Entity<RoleHierarchy>()
        .HasKey(rh => new { rh.ParentRoleId, rh.ChildRoleId });

            modelBuilder.Entity<RoleHierarchy>()
                .HasOne(rh => rh.ParentRole)
                .WithMany(r => r.ChildRoles)
                .HasForeignKey(rh => rh.ParentRoleId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RoleHierarchy>()
                .HasOne(rh => rh.ChildRole)
                .WithMany(r => r.ParentRoles)
                .HasForeignKey(rh => rh.ChildRoleId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<PayInformation>()
            .HasOne(pi => pi.User)
            .WithOne(u => u.PayInformation)
            .HasForeignKey<PayInformation>(pi => pi.UserId);

            modelBuilder.Entity<UserDTO>()
            .Property(u => u.RefreshToken)
            .HasMaxLength(512);

            modelBuilder.Entity<UserDTO>()
                .Property(u => u.RefreshTokenExpiryTime);

            modelBuilder.Entity<UserDTO>()
                .HasOne(u => u.JobTitles)
                .WithMany(j => j.Users)
                .HasForeignKey(u => u.JobId);

            modelBuilder.Entity<UserDTO>()
             .HasOne(u => u.CurrentAddress)
             .WithOne(j => j.User)
             .HasForeignKey<Address>(u => u.UserId);

            modelBuilder.Entity<EmergencyContact>()
             .HasOne(u => u.User)
             .WithMany(j => j.EmergencyContacts)
             .HasForeignKey(u => u.UserId);

            modelBuilder.Entity<SystemAnnouncements>()
                .HasOne(sa => sa.Poster)
                .WithMany(u => u.Announcements);

            modelBuilder.Entity<SystemAnnouncements>()
                .HasKey(sa => sa.Announcement_Id);
            modelBuilder.Entity<EmergencyContact>()
                .HasKey(sa => sa.ContactId);
        }
    }
}
