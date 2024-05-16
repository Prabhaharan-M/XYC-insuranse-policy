using Microsoft.AspNetCore.Authentication.Cookies;

namespace Demo2
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            //builder.Services.AddIdentity<IdentityUser, IdentityRole>();
            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options =>
            {
                options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
                options.LoginPath = "/Home/Login";
                options.AccessDeniedPath = "/Home/Login";
                
            });

            builder.Services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(10);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
            });
            //builder.Services.AddDbContext<InsuranceContext>(options => options.UseSqlServer());
            builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            // Add services to the container.
            builder.Services.AddControllersWithViews();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseStaticFiles();

            app.UseRouting();
            app.UseSession();
            app.UseAuthentication();

            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=HomePage}/{id?}");

            app.Run();
        }
    }
}