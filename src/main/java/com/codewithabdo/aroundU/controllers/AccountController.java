package com.codewithabdo.aroundU.controllers;

import com.codewithabdo.aroundU.models.AppUser;
import com.codewithabdo.aroundU.models.LoginDto;
import com.codewithabdo.aroundU.models.RegisterDto;
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
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

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

    try {
        // Check for duplicate username
        if (appUserRepository.findByUsername(registerDto.getUsername()) != null) {
            response.put("status", false);
            response.put("message", "You entered bad data");
            return ResponseEntity.badRequest().body(response); // Return 400 with bad data message
        }

        // Check for duplicate email
        if (appUserRepository.findByEmail(registerDto.getEmail()) != null) {
            response.put("status", false);
            response.put("message", "You entered bad data");
            return ResponseEntity.badRequest().body(response); // Return 400 with bad data message
        }

        // Save the user
        appUserRepository.save(appUser);

        // Generate JWT token
        String jwtToken = createJwtToken(appUser);

        // Add default profile image to response
        String defaultProfileImage = "https://example.com/default-profile.png"; // Replace with your image URL
        response.put("status", true);
        response.put("token", jwtToken);
        response.put("user", appUser);
        response.put("profileImage", defaultProfileImage);

        return ResponseEntity.ok(response); // Return 200 OK with success response
    } catch (Exception ex) {
        ex.printStackTrace();
        response.put("status", false);
        response.put("message", "An error occurred during registration.");
    }

    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response); // Return 500 for server-side error
}





    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @Valid @RequestBody LoginDto loginDto,
            BindingResult result) {

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
                response.put("message", "Bad username or password");
                return ResponseEntity.badRequest().body(response); // Return 400 if user not found
            }

            // Generate JWT token
            String jwtToken = createJwtToken(appUser);

            // Add default profile image if the user does not have one
            String defaultProfileImage = "https://example.com/default-profile.png"; // Replace with your default image URL
            String profileImage = appUser.getProfileImage() != null ? appUser.getProfileImage() : defaultProfileImage;

            // Populate successful response
            response.put("status", true);
            response.put("token", jwtToken);
            response.put("user", appUser);
            response.put("profileImage", profileImage); // Include profile image in response

            return ResponseEntity.ok(response); // Return 200 OK with user details and token
        } catch (Exception ex) {
            // Handle authentication failure
            response.put("status", false);
            response.put("message", "Bad username or password");
            return ResponseEntity.badRequest().body(response); // Return 400 for invalid credentials
        }
    }









    private String createJwtToken (AppUser appUser){
        Instant now =Instant.now();
        JwtClaimsSet claims= JwtClaimsSet.builder()
                .issuer(jwtIssuer)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(24*3600))
                .subject(appUser.getUsername())
                .claim("role",appUser.getRole())
                .build();
        var encoder =new NimbusJwtEncoder(
                new ImmutableSecret<>(jwtSecretKey.getBytes()));
        var params= JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(),claims);
        return encoder.encode(params).getTokenValue();
    }
}
