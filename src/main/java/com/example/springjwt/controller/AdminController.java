package com.example.springjwt.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody //문자열 데이터 응답
public class AdminController {

    @GetMapping("/admin")
    public String adminPage(){
        return "admin Controller";
    }
}
