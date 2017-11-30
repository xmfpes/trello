package com.trello.controller;

import javax.servlet.http.HttpServletRequest;

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
	public String loginForm(HttpServletRequest req) {
		String referer = req.getHeader("Referer");
		req.getSession().setAttribute("prevPage", referer);
		return "login";
	}
}
