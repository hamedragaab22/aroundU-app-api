package com.codewithabdo.aroundU.repositories;

import com.codewithabdo.aroundU.models.AppUser;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface AppUserRepository extends MongoRepository<AppUser, String> {
    // Find user by username
    public AppUser findByUsername(String username);

    // Find user by email
    public AppUser findByEmail(String email);

    // Find user by token
    public AppUser findByToken(String token);
}