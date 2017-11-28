package com.trello.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
	@GetMapping("")
	public String index() {
		return "index";
	}
	@GetMapping("/signUp")
	public String signUpForm() {
		return "signUp";
	}
	@GetMapping("/login")
	public String loginForm() {
		return "login";
	}
}
