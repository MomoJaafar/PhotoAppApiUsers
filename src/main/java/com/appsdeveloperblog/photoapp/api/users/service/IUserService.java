package com.appsdeveloperblog.photoapp.api.users.service;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.appsdeveloperblog.photoapp.api.users.shared.UserDto;

public interface IUserService extends UserDetailsService{

	UserDto createUser(UserDto userdetails);
	UserDto getUserDetailsByEmail(String email);
}
