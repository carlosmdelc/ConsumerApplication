using Consumer.Infra.Data;
using Consumer.Infra.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

var identityConnectionString = builder.Configuration.GetConnectionString("SqliteConsumerConnection");

builder.Services.AddDbContext<AppIdentityDbContext>(options =>
{
    //options.UseSqlServer(identityConnectionString);
    options.UseSqlite(identityConnectionString);
});

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<AppIdentityDbContext>();

builder.Services.ConfigureApplicationCookie(options =>
{    
    options.AccessDeniedPath = "/Account/NoAccess";
});

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 6;
    options.Password.RequiredUniqueChars = 1;
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);
    options.SignIn.RequireConfirmedEmail = false;
});

builder.Services.AddAuthorization(options =>
{
	options.AddPolicy(RoleDetails.Admin, policy => policy.RequireRole(RoleDetails.Admin));
	options.AddPolicy("AdminAndUser", policy => policy.RequireRole(RoleDetails.Admin).RequireRole(RoleDetails.User));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
