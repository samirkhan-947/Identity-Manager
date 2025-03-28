﻿using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models
{
    public class ResetViewModel
    {
        [Required]
        [EmailAddress]
        [Display(Name ="Email")]
        public string Email { get; set; }
        [Required]
        [StringLength(100,ErrorMessage ="The {0} must be at least {2} characters long.",MinimumLength =6)]
        [Display(Name ="Password")]
        public string Password { get; set; }
        [DataType(DataType.Password)]
        [Display(Name ="Confirm Password")]
        [Compare("Password",ErrorMessage ="The Password and confirmation do not match")]
        public string ConfirmPassword { get; set; }
       
        public string Code { get; set; }
    }
}
