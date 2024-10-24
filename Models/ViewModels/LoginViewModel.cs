using System.ComponentModel.DataAnnotations;

namespace ConsumerApplication.Models.ViewModels
{
    public class LoginViewModel
    {
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }
}
