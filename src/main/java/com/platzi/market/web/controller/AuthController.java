package com.platzi.market.web.controller;

import com.platzi.market.domain.dto.AuthenticacionRequest;
import com.platzi.market.domain.dto.AuthenticationResponse;
import com.platzi.market.domain.service.PlatziUserDetailService;
import com.platzi.market.web.security.JWTUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/auth", method = RequestMethod.GET)
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private PlatziUserDetailService platizUserDetailService;

    @Autowired
    private JWTUtil jwtUtil;

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> createToken(@RequestBody AuthenticacionRequest request){
        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
            UserDetails userDetails = platizUserDetailService.loadUserByUsername(request.getUsername());
            String jwt = jwtUtil.generateToken(userDetails);

            return new ResponseEntity<>(new AuthenticationResponse(jwt), HttpStatus.OK);

        } catch (BadCredentialsException e){
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }



    }
}
