package io.security.corespringsecurity.controller.admin;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class AdminController {

    @GetMapping(value="/admin")
    public String home() throws Exception {
        return "admin/home";
    }

}


