package com.codewithabdo.aroundU.controllers;

import com.codewithabdo.aroundU.models.AppUser;
import com.codewithabdo.aroundU.models.LoginDto;
import com.codewithabdo.aroundU.models.RegisterDto;
import com.codewithabdo.aroundU.models.UpdateUserDto;
import com.codewithabdo.aroundU.repositories.AppUserRepository;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import jakarta.validation.Valid;
import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/account")
public class AccountController {
    @Value("${security.jwt.secret-key}")
    private String jwtSecretKey;
    @Value("${security.jwt.issuer}")
    private String jwtIssuer;
    @Autowired
    private AppUserRepository appUserRepository;
    @Autowired
    private AuthenticationManager authenticationManager;
//    @GetMapping("/profile")
//    public ResponseEntity<Object>profile(Authentication auth){
//        var response=new HashMap<String,Object>();
//        response.put("Username",auth.)
//    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(
            @Valid @RequestBody RegisterDto registerDto, BindingResult result) {

        Map<String, Object> response = new HashMap<>();

        // Handle validation errors
        if (result.hasErrors()) {
            Map<String, String> errorsMap = new HashMap<>();
            for (Object errorObj : result.getAllErrors()) {
                var error = (FieldError) errorObj;
                errorsMap.put(error.getField(), error.getDefaultMessage());
            }
            response.put("status", false);
            response.put("errors", errorsMap);
            return ResponseEntity.badRequest().body(response); // Return 400 with validation errors
        }


        var bCryptEncoder = new BCryptPasswordEncoder();
        AppUser appUser = new AppUser();
        appUser.setFullName(registerDto.getFullName());
        appUser.setUsername(registerDto.getUsername());
        appUser.setEmail(registerDto.getEmail());
        appUser.setRole("client");
        appUser.setCreatedAt(new Date());
        appUser.setPassword(bCryptEncoder.encode(registerDto.getPassword()));
        appUser.setProfileImage("https://student.valuxapps.com/storage/assets/defaults/user.jpg"); // Default profile image

        try {
            // Check for duplicate username
            if (appUserRepository.findByUsername(registerDto.getUsername()) != null) {
                response.put("status", false);
                response.put("message", "You Enter Bad Data.");
                return ResponseEntity.badRequest().body(response); // Return 400 with duplicate username error
            }

            // Check for duplicate email
            if (appUserRepository.findByEmail(registerDto.getEmail()) != null) {
                response.put("status", false);
                response.put("message", "You Enter Bad Data.");
                return ResponseEntity.badRequest().body(response); // Return 400 with duplicate email error
            }

            // Save the user
            appUser = appUserRepository.save(appUser);

            // Generate JWT token and save it to the database
            String jwtToken = createJwtToken(appUser);
            appUser.setToken(jwtToken);
            appUserRepository.save(appUser);

            // Populate response
            response.put("status", true);
//            response.put("token", jwtToken);
            response.put("user", appUser);

            return ResponseEntity.ok(response); // Return 200 OK with success response
        } catch (Exception ex) {
            ex.printStackTrace();
            response.put("status", false);
            response.put("message", "An error occurred during registration.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response); // Return 500 for server error
        }
    }






    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @Valid @RequestBody LoginDto loginDto, BindingResult result) {

        Map<String, Object> response = new HashMap<>();

        // Handle validation errors
        if (result.hasErrors()) {
            Map<String, String> errorsMap = new HashMap<>();
            for (Object errorObj : result.getAllErrors()) {
                var error = (FieldError) errorObj;
                errorsMap.put(error.getField(), error.getDefaultMessage());
            }
            response.put("status", false);
            response.put("errors", errorsMap);
            return ResponseEntity.badRequest().body(response); // Return 400 for validation errors
        }

        try {
            // Authenticate the user
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginDto.getUsername(),
                            loginDto.getPassword()
                    )
            );

            // Fetch user details
            AppUser appUser = appUserRepository.findByUsername(loginDto.getUsername());
            if (appUser == null) {
                response.put("status", false);
                response.put("message", "Invalid username or password.");
                return ResponseEntity.badRequest().body(response); // Return 400 if user not found
            }

            // Generate new JWT token and update the database
            String jwtToken = createJwtToken(appUser);
            appUser.setToken(jwtToken);
            appUserRepository.save(appUser);

            // Populate response
            response.put("status", true);
//            response.put("token", jwtToken);
            response.put("user", appUser);

            return ResponseEntity.ok(response); // Return 200 OK with user details and token
        } catch (Exception ex) {
            response.put("status", false);
            response.put("message", "Invalid username or password.");
            return ResponseEntity.badRequest().body(response); // Return 400 for invalid credentials
        }
    }

    @DeleteMapping("/deleteUser")
    public ResponseEntity<Map<String, Object>> deleteUserByToken(
            @RequestHeader("Authorization") String token) {

        Map<String, Object> response = new HashMap<>();

        try {
            // Remove "Bearer " prefix if present
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            }

            // Configure NimbusJwtDecoder with the secret key
            var decoder = NimbusJwtDecoder.withSecretKey(new ImmutableSecret<>(jwtSecretKey.getBytes()).getSecretKey())
                    .macAlgorithm(MacAlgorithm.HS256)
                    .build();

            // Decode the token
            var jwt = decoder.decode(token);

            // Extract the username (subject) from the token claims
            String username = jwt.getClaimAsString("sub");

            // Retrieve user from the database
            AppUser appUser = appUserRepository.findByUsername(username);
            if (appUser == null) {
                response.put("status", false);
                response.put("message", "User not found.");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response); // 404 if user not found
            }

            // Delete the user
            appUserRepository.delete(appUser);

            // Populate response
            response.put("status", true);
            response.put("message", "User deleted successfully.");

            return ResponseEntity.ok(response); // Return 200 OK with success message
        } catch (Exception ex) {
            ex.printStackTrace();
            response.put("status", false);
            response.put("message", "Invalid or expired token.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response); // 401 for invalid/expired token
        }
    }
    @PutMapping("/user/update")
    public ResponseEntity<Map<String, Object>> updateUserByToken(
            @RequestHeader("Authorization") String token,
            @RequestBody Map<String, String> updates) {

        Map<String, Object> response = new HashMap<>();

        try {
            // Remove "Bearer " prefix if present
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            }

            // Configure NimbusJwtDecoder with the secret key
            var decoder = NimbusJwtDecoder.withSecretKey(new ImmutableSecret<>(jwtSecretKey.getBytes()).getSecretKey())
                    .macAlgorithm(MacAlgorithm.HS256).build();

            // Decode the token
            var jwt = decoder.decode(token);

            // Extract the username (subject) from the token claims
            String username = jwt.getClaimAsString("sub");

            // Retrieve user from the database
            AppUser appUser = appUserRepository.findByUsername(username);
            if (appUser == null) {
                response.put("status", false);
                response.put("message", "User not found.");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
            }

            // Update fields if they exist in the request
            if (updates.containsKey("fullName")) {
                appUser.setFullName(updates.get("fullName"));
            }
            if (updates.containsKey("phone")) {
                appUser.setPhone(updates.get("phone"));
            }
            if (updates.containsKey("address")) {
                appUser.setAddress(updates.get("address"));
            }
            if (updates.containsKey("profileImage")) {
                appUser.setProfileImage(updates.get("profileImage"));
            }

            // Save the updated user data
            appUserRepository.save(appUser);

            // Populate response
            response.put("status", true);
            response.put("message", "User updated successfully.");
            response.put("user", appUser);

            return ResponseEntity.ok(response);
        } catch (Exception ex) {
            ex.printStackTrace();
            response.put("status", false);
            response.put("message", "Invalid or expired token.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }








    @GetMapping("/user")
    public ResponseEntity<Map<String, Object>> getUserByToken(
            @RequestHeader("Authorization") String token) {

        Map<String, Object> response = new HashMap<>();

        try {
            // Remove "Bearer " prefix if present
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            }

            // Configure NimbusJwtDecoder with the secret key
            var decoder = NimbusJwtDecoder.withSecretKey(new ImmutableSecret<>(jwtSecretKey.getBytes()).getSecretKey()).macAlgorithm(MacAlgorithm.HS256).build();


            // Decode the token
            var jwt = decoder.decode(token);

            // Extract the username (subject) from the token claims
            String username = jwt.getClaimAsString("sub");

            // Retrieve user from the database
            AppUser appUser = appUserRepository.findByUsername(username);
            if (appUser == null) {
                response.put("status", false);
                response.put("message", "User not found.");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response); // 404 if user not found
            }

            // Populate response
            response.put("status", true);
            response.put("user", appUser);

            return ResponseEntity.ok(response); // Return 200 OK with user data
        } catch (Exception ex) {
            ex.printStackTrace();
            response.put("status", false);
            response.put("message", "Invalid or expired token.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response); // 401 for invalid/expired token
        }
    }
















    private String createJwtToken(AppUser appUser) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtIssuer)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(24 * 3600))
                .subject(appUser.getUsername())
                .claim("role", appUser.getRole())
                .build();

        var encoder = new NimbusJwtEncoder(
                new ImmutableSecret<>(jwtSecretKey.getBytes()));
        var params = JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(), claims);
        String token = encoder.encode(params).getTokenValue();

        // Save the token to the user entity
        appUser.setToken(token);
        appUserRepository.save(appUser); // Assuming you have a JPA repository

        return token;
    }

}
