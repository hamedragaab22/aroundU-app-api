package com.codewithabdo.aroundU.repositories;

import com.codewithabdo.aroundU.models.AppUser;
import org.springframework.data.mongodb.repository.MongoRepository;
import java.util.Optional;

public interface AppUserRepository extends MongoRepository<AppUser, String> { // Use String for ID type
    public AppUser findByUsername(String username);
    public AppUser findByEmail(String email);
    AppUser findByToken(String token);
}