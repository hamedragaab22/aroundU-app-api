package com.codewithabdo.aroundU.repositories;

import com.codewithabdo.aroundU.models.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser,Integer> {
    public AppUser findByUsername(String username);
    public AppUser findByEmail(String email);
    AppUser findByToken(String token);

}
