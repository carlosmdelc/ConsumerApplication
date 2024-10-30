using Consumer.Infra.Data;
using Consumer.Infra.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ConsumerApplication.Controllers
{
    public class RoleController : Controller
    {
	    private const string DELETE_SUCCESS = "Role deleted successfully";
	    private const string CREATE_SUCCESS = "Role created successfully";
	    private const string UPDATE_SUCCESS = "Role updated successfully";
	    private const string DELETE_ERROR = "Cannot delete this role, since there are users assigned to this role.";

		private readonly AppIdentityDbContext _db;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleController(AppIdentityDbContext db, UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public IActionResult Index()
        {
            var roles = _db.Roles.ToList();

            return View(roles);
        }

        [HttpGet]
        public IActionResult Upsert(string roleId)
        {
            if (String.IsNullOrEmpty(roleId))
            {
                // Create
                return View();
            }
            else
            {
                // Update
                var roleFromDb = _db.Roles.FirstOrDefault(r => r.Id == roleId);

                return View(roleFromDb);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
		public async Task<IActionResult> Upsert(IdentityRole identityRole)
        {
            if (await _roleManager.RoleExistsAsync(identityRole.Name))
			{
                // Error
			}

			if (String.IsNullOrEmpty(identityRole.NormalizedName))
	        {
		        // Create
		        await _roleManager.CreateAsync(new IdentityRole() { Name = identityRole.Name });
		        TempData[RoleDetails.Success] = CREATE_SUCCESS;
	        }
	        else
	        {
		        // Update
		        var roleFromDb = _db.Roles.FirstOrDefault(u => u.Id == identityRole.Id);

				roleFromDb.Name = identityRole.Name;
                roleFromDb.NormalizedName = identityRole.Name.ToUpper();

                await _roleManager.UpdateAsync(roleFromDb);
                TempData[RoleDetails.Success] = UPDATE_SUCCESS;
	        }

            return RedirectToAction(nameof(Index));
		}

		[HttpPost]
		[ValidateAntiForgeryToken]
		public async Task<IActionResult> Delete(string roleId)
		{
			var roleFromDb = _db.Roles.FirstOrDefault(r => r.Id == roleId);

			if (roleFromDb != null)
			{
				if (_db.UserRoles.Any(u => u.RoleId == roleId))
				{
					TempData[RoleDetails.Error] = DELETE_ERROR;
					return RedirectToAction(nameof(Index));
				}

				await _roleManager.DeleteAsync(roleFromDb);
				TempData[RoleDetails.Success] = DELETE_SUCCESS;
			}
			
			return RedirectToAction(nameof(Index));
		}
	}
}
