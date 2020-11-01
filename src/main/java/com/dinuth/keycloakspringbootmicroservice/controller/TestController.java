package 	com.dinuth.keycloakspringbootmicroservice.controller;

import java.security.Principal;

import javax.annotation.security.RolesAllowed;

import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {
	Logger log = LoggerFactory.getLogger(this.getClass());
	
	@Autowired
	AccessToken accessToken;
	
    @RequestMapping(value = "/anonymous", method = RequestMethod.GET)
    public ResponseEntity<String> getAnonymous() {
    	log.info("Pasando por get de Anomimous");;
        return ResponseEntity.ok("Hello Anonymous");
    }

    @RolesAllowed({"app-user","user"})
    @RequestMapping(value = "/user", method = RequestMethod.GET)
    public ResponseEntity<String> getUser(@RequestHeader String Authorization,Principal principal,Authentication auth) {
//    	AccessToken accessToken= ((KeycloakSecurityContext) ((KeycloakAuthenticationToken) auth).getCredentials()).getToken();

    	if (accessToken==null)
    		log.info("Sin acceso");
    	else
    	{
    		var  roles = accessToken.getResourceAccess();
    		roles.forEach((k,v) -> log.info("Rol: "+v.getRoles().toString()));
    		log.info("Nombre del principal Principal {} ",auth.getDetails().toString() );
    	}
    	

        return ResponseEntity.ok("Hello User: "+Authorization);
    }

    @RolesAllowed("admin")
    @RequestMapping(value = "/admin", method = RequestMethod.GET)
    public ResponseEntity<String> getAdmin(@RequestHeader String Authorization) {
        return ResponseEntity.ok("Hello Admin");
    }

    @RolesAllowed({ "admin", "user" })
    @RequestMapping(value = "/all-user", method = RequestMethod.GET)
    public ResponseEntity<String> getAllUser(@RequestHeader String Authorization) {
        return ResponseEntity.ok("Hello All User");
    }

}