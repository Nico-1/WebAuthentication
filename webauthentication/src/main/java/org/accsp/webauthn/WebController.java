package org.accsp.webauthn;


import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.Collections;
import java.util.List;

import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.authenticator.*;
import com.webauthn4j.converter.jackson.WebAuthnCBORModule;
import com.webauthn4j.converter.jackson.WebAuthnJSONModule;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.*;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.CollectionUtil;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;


@RestController
public class WebController {

	
	    @RequestMapping("/greeting")
	    public ObjectNode greeting() {
	    	
	    	ObjectNode aNode = new ObjectMapper().createObjectNode();
    		aNode.put("status", "API is running and active 1.0.2");
    		return aNode;
    		
	   }
	    
	    @RequestMapping("/credential")
	    public PublicKeyCredentialRequestOptions credential() {
	    	
	    	
	    String rpId = "example.com";
        long timeout = 0;
        Challenge challenge = new DefaultChallenge();
        byte[] credentialId = new byte[32];
        List<PublicKeyCredentialDescriptor> allowCredentials = Collections.singletonList(
                new PublicKeyCredentialDescriptor(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        credentialId,
                        CollectionUtil.unmodifiableSet(AuthenticatorTransport.USB, AuthenticatorTransport.NFC, AuthenticatorTransport.BLE)
                )
        );

        PublicKeyCredentialRequestOptions credentialRequestOptions = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                rpId,
                allowCredentials,
                UserVerificationRequirement.DISCOURAGED,
                null
);
        
        return credentialRequestOptions;
        
        
	    }
	    
	    @RequestMapping("/authenticate")
	    public ObjectNode authenticate(@RequestBody String uInfo) {
	    	
	    	
	    	JsonConverter jConvert = new JsonConverter();
	    	ObjectNode jsonRoot ;
	    	
	    	ObjectMapper jsonMapper = new ObjectMapper();
	    	jsonMapper.registerModule(new WebAuthnCBORModule(jConvert, jConvert.getCborConverter()));
	    	jsonMapper.registerModule(new WebAuthnJSONModule(jConvert, jConvert.getCborConverter()));
	    	
	    
	    	try {
	    	jsonRoot =  (ObjectNode) new ObjectMapper().readTree(uInfo) ;
	    	
	    	}
	    	catch (Exception e ) {
	    		ObjectNode errorNode = new ObjectMapper().createObjectNode();
	    		errorNode.put("error 1", e.getMessage());
	    		return errorNode;
	    
	    	}
	    	
	    	

	    	String rpId = jsonRoot.get("hostname").asText();
	    	
	    	
	    	Origin origin = new Origin("https", rpId, 
	    								jsonRoot.get("port").asInt()); 
	    	
	    	
	    	byte[] tokenBindingId = null /* set tokenBindingId */;
	    	//
	    	boolean userVerificationRequired = jsonRoot.get("authData")					   
						.get("flagUV").asBoolean();
	    	
	    	
	    	//boolean userVerificationRequired = false;
	    	
	    	byte[] clientDataJSON = jsonRoot.get("clientDataJSON").asText().getBytes();
	    	byte[] authenticatorData = Base64.getDecoder().decode(jsonRoot.get("authenticatorData").asText().getBytes());
	    	byte[] signature = Base64.getDecoder().decode(jsonRoot.get("signature").asText().getBytes());
	    	
	    	String challengeStr = "";
	    	
	    	try {	    	
	    		
	    	challengeStr =	Base64.getEncoder().encodeToString(jsonRoot.get("challenge").asText().getBytes("utf-8"));
	    	}
	    	catch(Exception e) {
	    		
	    		ObjectNode errorNode = new ObjectMapper().createObjectNode();
	    		errorNode.put("error 2", e.getMessage());
	    		return errorNode;
	    	}
	    	
	    	Challenge challenge = new DefaultChallenge(challengeStr);
	    	
	        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

	        
	        byte[] credId = Base64.getDecoder().decode(jsonRoot.get("authData")
	    												   .get("attestedCredentialData")
	    													.get("credentialId").asText().getBytes());
	    	
	      	

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
	        
	    	AAGUID aaguid = new AAGUID(jsonRoot.get("authData")
	    										.get("attestedCredentialData")
	    										.get("aaguid")
	    										.get("value").asText());
		    
	    	
	    	String credKeyText = jsonRoot.get("authData")
						.get("attestedCredentialData")
						 .get("credentialPublicKey").toString();
	    	
	    	
	    	 
	    	int lastSignCount =  jsonRoot.get("lastSignCount").asInt();
	    
	    	
	    	 
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
	    		errorNode.put("error 4", e.getMessage());
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
	    	boolean userVerificationRequired = uReg.verifyUser;
	    	
	    	WebAuthnRegistrationContext registrationContext = new WebAuthnRegistrationContext(clientDataJSON, attestationObject, serverProperty, userVerificationRequired);
	    	
	    	WebAuthnRegistrationContextValidator webAuthnRegistrationContextValidator =
	    	        WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator();
	    	
	    
	    	WebAuthnRegistrationContextValidationResponse response = webAuthnRegistrationContextValidator.validate(registrationContext);
    	
	    	
	    	try {
	    		
	    		//JsonNode statement = jsonMapper.readTree(jsonMapper.writeValueAsString(response.getAttestationObject().getAttestationStatement()));
	    		JsonNode attData = jsonMapper.readTree(jsonMapper.writeValueAsString(response.getAttestationObject().getAuthenticatorData()));

	    			     	  	
	     	  	ObjectNode responseNode = jsonMapper.createObjectNode();
	     	  	responseNode.set("authData", attData);
	     	  	//responseNode.set("statetement", statement);
	  
	     	  	
	     	  	return responseNode;       
	          
	     	
	    	}
	    	catch (Exception e) {
	    		 
	    		System.out.println("Got issues "+ e.getMessage());
	    	}
	    	
	    	return jsonMapper.createObjectNode();
	    	 
	    }
	    

	
}



