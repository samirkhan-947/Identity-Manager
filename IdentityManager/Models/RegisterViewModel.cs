﻿using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models
{
    public class RegisterViewModel
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
        [Required]
        public string Name { get; set; }

        public IEnumerable<SelectListItem> RoleList { get; set; } = new List<SelectListItem>();
        public string RoleSelected { get; set; }
    }
}
