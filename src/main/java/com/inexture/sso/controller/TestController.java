package com.inexture.sso.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class TestController {
   
	@GetMapping("/login")
	public String login() {
		return "Index";
	}
}