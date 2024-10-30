using System.Security.Claims;
using Consumer.Infra.Data;
using Consumer.Infra.Models;
using ConsumerApplication.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ConsumerApplication.Controllers
{
    public class UserController : Controller
    {
        private const string NO_ROLE = "None";
        private const string USER_DELETE_ROLE_ERROR = "Error while removing roles";
        private const string USER_ADD_ROLE_ERROR = "Error while adding roles";
        private const string USER_ASSIGN_ROLE_SUCCESS = "Roles assigned successfully";
        private const string USER_UNLOCK_SUCCESS = "User unlocked successfully";
        private const string USER_LOCK_SUCCESS = "User Locked successfully";
        private const string USER_DELETE_SUCCESS = "User deleted successfully";
        private const string CLAIMS_DELETE_ERROR = "Error while removing claims";
        private const string CLAIMS_ADD_ERROR = "Error while adding claims";
        private const string CLAIMS_ADD_SUCCESS = "Claims assigned successfully";

		private readonly AppIdentityDbContext _db;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserController(AppIdentityDbContext db, UserManager<ApplicationUser> userManager, 
	        RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _userManager = userManager;
            _roleManager = roleManager;
        }
        public async Task<IActionResult> Index()
        {
            var usersList = _db.ApplicationUsers.ToList();

            foreach (var user in usersList)
            {
                user.Role = String.Empty;

                var userRoles = await _userManager.GetRolesAsync(user) as List<string>;

                user.Role = userRoles != null ? String.Join(", ", userRoles) : NO_ROLE;
            }

            return View(usersList);
        }

        public async Task<IActionResult> ManageRole(string userId)
        {
	        var user = await _userManager.FindByIdAsync(userId);
	        if (user == null)
		        return NotFound();

	        List<string>? existingUserRoles = await _userManager.GetRolesAsync(user) as List<string>;

	        var rolesModel = new RolesViewModel()
	        {
		        User = user
	        };

	        foreach (var identityRole in _roleManager.Roles)
	        {
		        RoleSelection roleSelection = new RoleSelection
		        {
			        RoleName = identityRole.Name
		        };

		        if (existingUserRoles.Any(r => r == identityRole.Name))
		        {
			        roleSelection.IsSelected = true;
		        }

		        rolesModel.RolesList.Add(roleSelection);
	        }

            return View(rolesModel);
        }

		[HttpPost]
		[ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageRole(RolesViewModel rolesViewModel)
        {
	        var user = await _userManager.FindByIdAsync(rolesViewModel.User.Id);
	        if (user == null)
		        return NotFound();

	        var formerUserRoles = await _userManager.GetRolesAsync(user);

	        var result = await _userManager.RemoveFromRolesAsync(user, formerUserRoles);

	        if (!result.Succeeded)
	        {
		        TempData[RoleDetails.Error] = USER_DELETE_ROLE_ERROR;
		        return View(rolesViewModel);
	        }

	        result = await _userManager.AddToRolesAsync(user,
		        rolesViewModel.RolesList
			        .Where(r => r.IsSelected).Select(y => y.RoleName));

	        if (!result.Succeeded)
	        {
		        TempData[RoleDetails.Error] = USER_ADD_ROLE_ERROR;
				return View(rolesViewModel);
	        }

	        TempData[RoleDetails.Success] = USER_ASSIGN_ROLE_SUCCESS;

	        return RedirectToAction(nameof(Index));
        }

		[HttpPost]
		[ValidateAntiForgeryToken]
        public async Task<IActionResult> LockUnlock(string userId)
        {
	        var user = await _userManager.FindByIdAsync(userId);
	        
	        if (user == null)
		        return NotFound();

	        if (user.LockoutEnd != null && user.LockoutEnd > DateTime.Now)
	        {
		        user.LockoutEnd = DateTime.Now;
		        TempData[RoleDetails.Success] = USER_UNLOCK_SUCCESS;
	        }
	        else
	        {
		        user.LockoutEnd = DateTime.Now.AddYears(100);
		        TempData[RoleDetails.Success] = USER_LOCK_SUCCESS;
	        }

	        await _db.SaveChangesAsync();

			return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string userId)
        {
	        var user = _db.ApplicationUsers.FirstOrDefault(u => u.Id == userId);

			if (user == null) 
				return NotFound();

			_db.ApplicationUsers.Remove(user);

			await _db.SaveChangesAsync();

			TempData[RoleDetails.Success] = USER_DELETE_SUCCESS;

			return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> ManageUserClaim(string userId)
        {
	        var user = await _userManager.FindByIdAsync(userId);
	        if (user == null)
		        return NotFound();

	        var existingUserClaims = await _userManager.GetClaimsAsync(user);

	        var claimsModel = new ClaimsViewModel()
	        {
		        User = user
	        };

	        foreach (Claim claim in ClaimsStore.Claims)
	        {
		        ClaimSelection userClaim = new ClaimSelection
		        {
			        ClaimType = claim.Type
		        };

		        if (existingUserClaims.Any(c => c.Type == claim.Type))
		        {
			        userClaim.IsSelected = true;
		        }

				claimsModel.ClaimsList.Add(userClaim);
	        }

	        return View(claimsModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageUserClaim(ClaimsViewModel claimsViewModel)
        {
	        var user = await _userManager.FindByIdAsync(claimsViewModel.User.Id);
	        if (user == null)
		        return NotFound();

	        var formerClaims = await _userManager.GetClaimsAsync(user);

	        var result = await _userManager.RemoveClaimsAsync(user, formerClaims);

	        if (!result.Succeeded)
	        {
		        TempData[RoleDetails.Error] = CLAIMS_DELETE_ERROR;
		        return View(claimsViewModel);
	        }

	        result = await _userManager.AddClaimsAsync(user,
		        claimsViewModel.ClaimsList
			        .Where(c => c.IsSelected).Select(y => new Claim(y.ClaimType, y.IsSelected.ToString())));

	        if (!result.Succeeded)
	        {
		        TempData[RoleDetails.Error] = CLAIMS_ADD_ERROR;
		        return View(claimsViewModel);
	        }

	        TempData[RoleDetails.Success] = CLAIMS_ADD_SUCCESS;

	        return RedirectToAction(nameof(Index));
        }
	}
}
