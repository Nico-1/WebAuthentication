package org.accsp.webauthn;


import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;



import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.authenticator.*;
import com.webauthn4j.converter.jackson.WebAuthnCBORModule;
import com.webauthn4j.converter.jackson.WebAuthnJSONModule;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.*;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.gson.*;

@RestController
public class WebController {

	
	    @RequestMapping("/greeting")
	    public ObjectNode greeting() {
	    	
	    	ObjectNode aNode = new ObjectMapper().createObjectNode();
    		aNode.put("status", "API is running and active 2.1");
    		return aNode;
    		
	   }
	    
	    
	    @RequestMapping("/authenticate")
	    public ObjectNode authenticate(@RequestBody String uInfo) {
	    	
	    	
	    	JsonConverter jConvert = new JsonConverter();
	    	
	    	ObjectMapper jsonMapper = new ObjectMapper();
	    	jsonMapper.registerModule(new WebAuthnCBORModule(jConvert, jConvert.getCborConverter()));
	    	jsonMapper.registerModule(new WebAuthnJSONModule(jConvert, jConvert.getCborConverter()));
	    	
	    	JsonParser jsonParser = new JsonParser();
	    	JsonObject jsonRoot = jsonParser.parse(uInfo).getAsJsonObject();
	    

	    	String rpId = jsonRoot.get("hostname").getAsString();
	    	Origin origin = new Origin("https", rpId, 
	    								jsonRoot.get("port").getAsInt()); 
	    	
	    	
	    	byte[] tokenBindingId = null /* set tokenBindingId */;
	    	//
	    	boolean userVerificationRequired = jsonRoot.getAsJsonObject("authData")					   
						.get("flagUV").getAsBoolean();
	    	
	    	//boolean userVerificationRequired = false;
	    	
	    	byte[] clientDataJSON = jsonRoot.get("clientDataJSON").getAsString().getBytes();
	    	byte[] authenticatorData = Base64.getDecoder().decode(jsonRoot.get("authenticatorData").getAsString().getBytes());
	    	byte[] signature = Base64.getDecoder().decode(jsonRoot.get("signature").getAsString().getBytes());
	    	
	    	String challengeStr = "";
	    	
	    	try {	    	
	    		
	    	challengeStr =	Base64.getEncoder().encodeToString(jsonRoot.get("challenge").getAsString().getBytes("utf-8"));
	    	}
	    	catch(Exception e) {
	    		
	    		ObjectNode errorNode = new ObjectMapper().createObjectNode();
	    		errorNode.put("error", e.getMessage());
	    		return errorNode;
	    	}
	    	
	    	Challenge challenge = new DefaultChallenge(challengeStr);
	    	
	        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

	        
	        byte[] credId = Base64.getDecoder().decode(jsonRoot.getAsJsonObject("authData")
	    												   .getAsJsonObject("attestedCredentialData")
	    													.get("credentialId").getAsString().getBytes());
	    	
	        
	      
    		

	        WebAuthnAuthenticationContext authenticationContext =
	                new WebAuthnAuthenticationContext(
	                        credId,
	                        clientDataJSON,
	                        authenticatorData,
	                        signature,
	                        serverProperty,
	                        userVerificationRequired
	                );
	        
	   	
	   	 
	        WebAuthnAuthenticationContextValidator webAuthnAuthenticationContextValidator =
	                new WebAuthnAuthenticationContextValidator();
	        
	    	AAGUID aaguid = new AAGUID(jsonRoot.getAsJsonObject("authData")
	    										.getAsJsonObject("attestedCredentialData")
	    										.getAsJsonObject("aaguid")
	    										.get("value").getAsString());
		    
	    	
	    	 
	    	String credKeyText = jsonRoot.getAsJsonObject("authData")
	    						.getAsJsonObject("attestedCredentialData")
	    						 .getAsJsonObject("credentialPublicKey").toString();
	    	
	    	
	    	 
	    	int lastSignCount =  jsonRoot.get("lastSignCount").getAsInt();
	    
	    
	    	 
	    	try {
	    	
	    	CredentialPublicKey credKey = jsonMapper.readValue(credKeyText, CredentialPublicKey.class);
	    
	    	AttestedCredentialData attData = new AttestedCredentialData(aaguid, credId,  credKey);
	    	
	    		
	    	 Authenticator authenticator =
		     	        new AuthenticatorImpl( // You may create your own Authenticator implementation to save friendly authenticator name
		     	                attData,
		     	                new NoneAttestationStatement(),
		     	                lastSignCount 
		     	        );
		    
	    	WebAuthnAuthenticationContextValidationResponse response = webAuthnAuthenticationContextValidator.validate( authenticationContext, authenticator);

	    	
	    	JsonNode result = jsonMapper.readTree(jsonMapper.writeValueAsString(response));
    		
    			     	  	
     	  	ObjectNode responseNode = jsonMapper.createObjectNode();
     	  	responseNode.set("result", result);
     	  	responseNode.put("signCount",  response.getAuthenticatorData().getSignCount());
     	  	
	
     	  	return responseNode ;
	    	
	    	}
	    	
	    	catch(Exception e) {
	    		ObjectNode errorNode = new ObjectMapper().createObjectNode();
	    		errorNode.put("error", e.getMessage());
	    		return errorNode;
	    		
	    		
	    	}
	     	
	  	    	
	    }
	    
	    
	    
	    @RequestMapping("/registration")
	    public ObjectNode newRegistration(@RequestBody UserRegistration uReg) {
	       //AuthenticatorData
	    	
	    	byte[] clientDataJSON = uReg.clientDataJSON.getBytes(); 
	    	
	    	String aObj  = uReg.attestationObject;
	    			
	    	byte[] attestationObject = Base64.getDecoder().decode(aObj.getBytes());
	    	
	    	try {
	    	uReg.challenge = Base64.getEncoder().encodeToString(uReg.challenge.getBytes("utf-8"));
	    	
	    	}catch(Exception e) {
	    		
	    		ObjectNode errorNode = new ObjectMapper().createObjectNode();
	    		errorNode.put("error", e.getMessage());
	    		return errorNode;
	    	}
	    	
	    	
	    	ObjectMapper jsonMapper = new ObjectMapper();
	    	jsonMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);

	    	

	    	Origin origin = new Origin("https", uReg.hostname, uReg.port); /* set origin */
	    	String rpId = uReg.hostname;
	    	Challenge challenge = new DefaultChallenge(uReg.challenge); /* set challenge */;
	    	byte[] tokenBindingId = null /* set tokenBindingId */;
	    	
	    	ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);
	    	boolean userVerificationRequired = false;
	    	
	    	WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(clientDataJSON, attestationObject, serverProperty, userVerificationRequired);
	    	
	    	WebAuthnRegistrationContextValidator webAuthnRegistrationContextValidator =
	    	        WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator();
	    	
	    
	    	WebAuthnRegistrationContextValidationResponse response = webAuthnRegistrationContextValidator.validate(registrationContext);
    	
	    	
	    	try {
	    		
	    		JsonNode statement = jsonMapper.readTree(jsonMapper.writeValueAsString(response.getAttestationObject().getAttestationStatement()));
	    		JsonNode attData = jsonMapper.readTree(jsonMapper.writeValueAsString(response.getAttestationObject().getAuthenticatorData()));

	    			     	  	
	     	  	ObjectNode responseNode = jsonMapper.createObjectNode();
	     	  	responseNode.set("authData", attData);
	     	  	responseNode.set("statetement", statement);
	  
	     	  	
	     	  	return responseNode;       
	          
	     	
	    	}
	    	catch (Exception e) {
	    		 
	    		System.out.println("Got issues "+ e.getMessage());
	    	}
	    	
	    	return jsonMapper.createObjectNode();
	    	 
	    }
	    

	
}



