using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;

namespace Middleware.JwtHelper
{
    public class JwtTokenHelper
    {
        private readonly IConfiguration _configuration;
        private readonly string _key;
        private readonly string _issuer;
        private readonly string _audience;

        // Constructor to initialize JWT settings from the configuration file
        public JwtTokenHelper(IConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration), "Configuration cannot be null.");
            _key = configuration["Jwt:Key"];
            _issuer = configuration["Jwt:Issuer"];
            _audience = configuration["Jwt:Audience"];
        }

        /// <summary>
        /// Generates a JWT token for authentication.
        /// </summary>
        /// <param name="email">User's email address</param>
        /// <param name="role">User's role (e.g., Admin, User)</param>
        /// <returns>JWT token as a string</returns>
        public string GenerateToken(string email, string role)
        {
            var key = Encoding.UTF8.GetBytes(_configuration["JwtSettings:Key"]);
            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Email, email), // Adding email claim
                    new Claim(ClaimTypes.Role, role)    // Adding role claim
                }),
                Expires = DateTime.UtcNow.AddHours(2), // Token expiration time
                Issuer = _configuration["JwtSettings:Issuer"],
                Audience = _configuration["JwtSettings:Audience"],
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        /// <summary>
        /// Generates a JWT token for password reset functionality.
        /// </summary>
        /// <param name="email">User's email address</param>
        /// <returns>Password reset token as a string</returns>
        public string GeneratePasswordResetToken(string email)
        {
            if (string.IsNullOrEmpty(email))
                throw new ArgumentNullException(nameof(email), "Email cannot be null or empty.");

            var keyString = _configuration["JwtSettings:Key"];
            if (string.IsNullOrEmpty(keyString))
                throw new ArgumentException("JWT SecretKey is missing or empty.");

            var key = Encoding.UTF8.GetBytes(keyString);
            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, email), // Subject claim
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Unique Token ID
                new Claim(ClaimTypes.Email, email), // Email claim
                new Claim("isPasswordReset", "true") // Custom claim indicating password reset
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["JwtSettings:Issuer"],
                audience: _configuration["JwtSettings:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1), // Token expires in 1 hour
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        /// <summary>
        /// Validates a JWT token and extracts claims.
        /// </summary>
        /// <param name="token">JWT token string</param>
        /// <returns>ClaimsPrincipal object containing user claims if the token is valid; otherwise, null</returns>
        public ClaimsPrincipal ValidateToken(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentNullException(nameof(token), "Token cannot be null or empty.");

            var keyString = _configuration["JwtSettings:Key"];
            if (string.IsNullOrEmpty(keyString))
                throw new ArgumentException("JWT SecretKey is missing or empty.");

            var key = Encoding.UTF8.GetBytes(keyString);
            var tokenHandler = new JwtSecurityTokenHandler();

            var validationParams = new TokenValidationParameters
            {
                ValidateIssuer = true, // Validate the token issuer
                ValidateAudience = true, // Validate the token audience
                ValidateLifetime = true, // Ensure the token is not expired
                ValidateIssuerSigningKey = true, // Validate the signing key
                ValidIssuer = _configuration["JwtSettings:Issuer"],
                ValidAudience = _configuration["JwtSettings:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(key) // Use the key for validation
            };

            try
            {
                var principal = tokenHandler.ValidateToken(token, validationParams, out SecurityToken validatedToken);

                // Log the validated claims (if needed)
                foreach (var claim in principal.Claims)
                {
                    // Console.WriteLine($"Claim Type: {claim.Type}, Value: {claim.Value}");
                }

                return principal; // Return user claims if token is valid
            }
            catch (SecurityTokenExpiredException)
            {
                // Token has expired
                return null;
            }
            catch (Exception ex)
            {
                // Token validation failed for another reason
                return null;
            }
        }
    }
}
