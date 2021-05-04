package com.example.springsecurity.auth;

import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component()
public class CustomUserDetailsService implements UserDetailsService {

	@Autowired()
	private UserRepository userRepo;
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user =  userRepo.findByUsername(username);
		if (Objects.isNull(user)){
			throw new UsernameNotFoundException("user not found!");
		}
		return new CustomUserDetails(user);
	}

}
