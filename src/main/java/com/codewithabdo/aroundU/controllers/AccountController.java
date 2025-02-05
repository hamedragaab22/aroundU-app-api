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
        appUser.setUsername(registerDto.getUsername());
        appUser.setEmail(registerDto.getEmail());
        appUser.setPhone(registerDto.getPhone());
        appUser.setRole("client");
        appUser.setCreatedAt(new Date());
        appUser.setPassword(bCryptEncoder.encode(registerDto.getPassword()));
        appUser.setProfileImage("https://student.valuxapps.com/storage/assets/defaults/user.jpg");

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
            response.put("message", "You signed up successfully."); // Add success message
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
            // Authenticate the user using email and password
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginDto.getEmail(),
                            loginDto.getPassword()
                    )
            );

            // Fetch user details by email
            AppUser appUser = appUserRepository.findByEmail(loginDto.getEmail());
            if (appUser == null) {
                response.put("status", false);
                response.put("message", "Invalid email or password.");
                return ResponseEntity.badRequest().body(response); // Return 400 if user not found
            }

            // Generate new JWT token and update the database
            String jwtToken = createJwtToken(appUser);
            appUser.setToken(jwtToken);
            appUserRepository.save(appUser);

            // Populate response
            response.put("status", true);
            response.put("message", "You logged in successfully."); // Add success message
            response.put("user", appUser);

            return ResponseEntity.ok(response); // Return 200 OK with user details and token
        } catch (Exception ex) {
            response.put("status", false);
            response.put("message", "Invalid email or password.");
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
                .issuer(jwtIssuer) // Issuer of the token
                .issuedAt(now) // Token creation time
                .expiresAt(now.plusSeconds(7 * 24 * 3600)) //  (7 days)
                .subject(appUser.getUsername()) // S(username)
                .claim("role", appUser.getRole()) //  user role
                .build();

        // Create JWT encoder
        var encoder = new NimbusJwtEncoder(
                new ImmutableSecret<>(jwtSecretKey.getBytes()));

        // Define JWT header and parameters
        var params = JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(), claims);

        // Encode the JWT token
        String token = encoder.encode(params).getTokenValue();

        // Save the token to the user entity
        appUser.setToken(token);
        appUserRepository.save(appUser); // Save the updated user entity

        return token; // Return the generated token
    }
}