package com.newland.uua.password;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.authentication.AuthenticationConverter;

/**
 * Author: leell
 * Date: 2023/2/12 23:59:10
 */
public class PasswordAuthenticationConverter implements AuthenticationConverter {
    /**
     * 是否支持此convert
     * @return
     */
//    public boolean support(String grantType){
//        return AuthorizationGrantType.PASSWORD
//    }
    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType=request.getParameter("grant_type");
        if(!grantType.equals(AuthorizationGrantType.PASSWORD.getValue())){
            return null;
        }

        return null;
    }
}
