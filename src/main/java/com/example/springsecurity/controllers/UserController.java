package com.example.springsecurity.controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.example.springsecurity.auth.User;
import com.example.springsecurity.auth.UserRepository;

@RestController()
@RequestMapping(path = "/api/")
public class UserController {
	@Autowired()
	private UserRepository userRepo;

	@RequestMapping(path = "/user", method = RequestMethod.GET)
	public ResponseEntity<List<User>> listUser() {
		return new ResponseEntity<>(userRepo.findAll(), HttpStatus.OK);
	}

	@RequestMapping(path = "/user", method = RequestMethod.POST)
	public ResponseEntity addUser(@RequestBody User user) {
		return new ResponseEntity(HttpStatus.CREATED);
	}
}
