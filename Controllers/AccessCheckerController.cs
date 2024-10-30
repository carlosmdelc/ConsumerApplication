using Consumer.Infra.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ConsumerApplication.Controllers
{
	[Authorize]
	public class AccessCheckerController : Controller
	{
		[AllowAnonymous]
		// Anyone can access
		public IActionResult AllAccess()
		{
			return View();
		}

		[Authorize]
		// Anyone logged in can access
		public IActionResult AuthorizedAccess()
		{
			return View();
		}

		[Authorize(Roles = $"{RoleDetails.Admin}, {RoleDetails.User}")]
		// Account with role of User or Admin can access
		public IActionResult UserOrAdminRoleAccess()
		{
			return View();
		}

		[Authorize(Policy = "AdminAndUser")]
		// Account with role of User or Admin can access
		public IActionResult UserAndAdminRoleAccess()
		{
			return View();
		}

		[Authorize(Policy = RoleDetails.Admin)]
		// Account with role of Admin can access
		public IActionResult AdminRoleAccess()
		{
			return View();
		}

		// Account with Admin role and Create claim can access
		public IActionResult AdminCreateAccess()
		{
			return View();
		}

		// Account with Admin role and Create, Edit and Delete claim can access
		public IActionResult AdminCreateEditDeleteAccess()
		{
			return View();
		}
	}
}
