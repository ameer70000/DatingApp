using System;
using System.Linq;
using System.Threading.Tasks;
using DatingApp.API.Models;
using Microsoft.EntityFrameworkCore;

namespace DatingApp.API.Data
{
    public class AuthRepository : IAuthRepository
    {
        private readonly DataContext context;
        public AuthRepository(DataContext context) => this.context = context;
        public async Task<User> Login(string userName, string password)
        {
            var user = await context.Users.FirstOrDefaultAsync(user=>user.UserName==userName);
            if(user==null||!VerifyPassword(password,user.PasswordSalt,user.PasswordHash))
            return null;
            return user;
        }

        private bool VerifyPassword(string password, byte[] passwordSalt, byte[] passwordHash)
        {
 using(var hmac= new System.Security.Cryptography.HMACSHA512(passwordSalt))
            {
                var calculatedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                if(calculatedHash.Length !=passwordHash.Length)
                return false;
                for (int i = 0; i < calculatedHash.Length; i++)
                {
                    if(calculatedHash[i]!=passwordHash[i])
                    return false;
                }
                return true;
            }
        }

        public async Task<User> Register(User user, string password)
        {
            byte[] passwordHash,passwordSalt;
            CreatePasswordHash(password,out passwordHash,out passwordSalt);
            user.PasswordHash=passwordHash;
            user.PasswordSalt=passwordSalt;
            await context.AddAsync(user);
            await context.SaveChangesAsync();

            return user;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using(var hmac= new System.Security.Cryptography.HMACSHA512())
            {
                passwordSalt=hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        public async Task<bool> UserExists(string userName)
        {
            return await context.Users.AnyAsync(user => user.UserName == userName);
        }
    }
}