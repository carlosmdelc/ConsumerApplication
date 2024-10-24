using Consumer.Infra.Models;
using ConsumerApplication.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace ConsumerApplication.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public AccountController(RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [AllowAnonymous]
        public async Task<IActionResult> Register(string? returnurl = null)
        {
            if(_roleManager.RoleExistsAsync(RoleDetails.Admin).Result == false)
            {
                await _roleManager.CreateAsync(new IdentityRole(RoleDetails.Admin));
                await _roleManager.CreateAsync(new IdentityRole(RoleDetails.User));
            }

            ViewData["ReturnUrl"] = returnurl;
            RegisterViewModel registerViewModel = new()
            {
                RolesList = _roleManager.Roles.Select(r => new SelectListItem
                {
                    Text = r.Name,
                    Value = r.Name
                }),
            };
            return View(registerViewModel);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel registerViewModel, string? returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;

            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = registerViewModel.Email,
                    Email = registerViewModel.Email,
                    Name = registerViewModel.Name
                };

                var result = await _userManager.CreateAsync(user, registerViewModel.Password);

                if (result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);

                    return LocalRedirect(returnurl ?? Url.Content("~/"));
                }

                AddErrors(result);
            }

            registerViewModel.RolesList = _roleManager.Roles.Select(r => new SelectListItem
            {
                Text = r.Name,
                Value = r.Name
            });

            return View(registerViewModel);
        }

        [AllowAnonymous]
        public IActionResult Login(string? returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel loginViewModel, string? returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(loginViewModel.Email, 
                    loginViewModel.Password, 
                    loginViewModel.RememberMe, 
                    lockoutOnFailure: true);

                if (result.Succeeded)
                {
                    return LocalRedirect(returnurl ?? Url.Content("~/"));
                }

                if (result.IsLockedOut)                
                    return View("Lockout");
                

                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return View(loginViewModel);
            }

            return View(loginViewModel);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Lockout()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogOff()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult NoAccess()
        {
            return View();
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }
    }
}
