package org.accsp.webauthn;

import java.util.concurrent.atomic.AtomicLong;



import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.Base64;



import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.authenticator.*;
import com.webauthn4j.converter.jackson.WebAuthnCBORModule;
import com.webauthn4j.converter.jackson.WebAuthnJSONModule;
import com.webauthn4j.converter.jackson.deserializer.CredentialPublicKeyEnvelope;
import com.webauthn4j.converter.jackson.deserializer.CredentialPublicKeyEnvelopeDeserializer;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.data.attestation.authenticator.EC2CredentialPublicKey;
import com.webauthn4j.data.attestation.authenticator.RSACredentialPublicKey;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.*;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;


import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.google.gson.*;

@RestController
public class WebController {

	
	    private static final String template = "Hello, %s!";
	    private final AtomicLong counter = new AtomicLong();

	    @RequestMapping("/greeting")
	    public String greeting(@RequestParam(value="name", defaultValue="World") String name) {
	        return counter.incrementAndGet() +  String.format(template, name);
	    }
	    
	    
	    @RequestMapping("/convert")
	    public String convert(@RequestBody String uInfo) {
	    	
	    	
	    	JsonConverter jConvert = new JsonConverter();
	    	
	    	ObjectMapper jsonMapper = new ObjectMapper();
	    	jsonMapper.registerModule(new WebAuthnCBORModule(jConvert, jConvert.getCborConverter()));
	    	jsonMapper.registerModule(new WebAuthnJSONModule(jConvert, jConvert.getCborConverter()));
	    	
	    	JsonParser jsonParser = new JsonParser();
	    	JsonObject jsonRoot = jsonParser.parse(uInfo).getAsJsonObject();
	    
	    	
	    	
	    	

	    	// Server properties
	    	//Origin origin = null /* set origin */;
	    	//String rpId = null /* set rpId */;
	    	String rpId = jsonRoot.get("hostname").getAsString();
	    	Origin origin = new Origin("https", rpId, 
	    								jsonRoot.get("port").getAsInt()); 
	    	
	    	
	    	byte[] tokenBindingId = null /* set tokenBindingId */;
	    	//
	    	boolean userVerificationRequired = jsonRoot.getAsJsonObject("authData")					   
						.get("flagUV").getAsBoolean();
	    	
	    	
	    	byte[] clientDataJSON = jsonRoot.get("clientDataJSON").getAsString().getBytes();
	    	byte[] authenticatorData = Base64.getDecoder().decode(jsonRoot.get("authenticatorData").getAsString().getBytes());
	    	byte[] signature = Base64.getDecoder().decode(jsonRoot.get("signature").getAsString().getBytes());
	    	Challenge challenge = new DefaultChallenge(jsonRoot.get("challenge").getAsString());
	    	
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
		      
	    	
	    	try {
	    	
	    	CredentialPublicKey credKey = jsonMapper.readValue(credKeyText, CredentialPublicKey.class);
	    
	    	AttestedCredentialData attData = new AttestedCredentialData(aaguid, credId,  credKey);
	    	
	    		
	    	 Authenticator authenticator =
		     	        new AuthenticatorImpl( // You may create your own Authenticator implementation to save friendly authenticator name
		     	                attData,
		     	                new NoneAttestationStatement(),
		     	                0
		     	        );
		    
	    	WebAuthnAuthenticationContextValidationResponse response = webAuthnAuthenticationContextValidator.validate( authenticationContext, authenticator);

	    	
	    	System.out.println ("sign count:" + response.getAuthenticatorData().getSignCount());
	
	    return  jsonMapper.writeValueAsString(response);
		    	
	    	//return "big";
	    	
	    	}
	    	
	    	catch(Exception e) {
	    		return "Error with parser, " + e.toString();
	    	}
	    	
	     	
	    //	return "done";
	    	
	    }
	    
	    
	    
	    @RequestMapping("/registration")
	    public AttestationObject newRegistration(@RequestBody UserRegistration uReg) {
	       //AuthenticatorData
	    	
	    	byte[] clientDataJSON = uReg.clientDataJSON.getBytes(); 
	    	
	    	String aObj  = uReg.attestationObject;
	    	String printRes;
	    			
	    	byte[] attestationObject = Base64.getDecoder().decode(aObj.getBytes());
	    	

	    	ObjectMapper jsonMapper = new ObjectMapper();
	    	

	    /**	ObjectMapper jsonMapper = new ObjectMapper()
	    	    .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
	    	    .setSerializationInclusion(Include.NON_ABSENT)
	    	    .registerModule(new Jdk8Module());**/

	    
	                
	    	
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
	    	//ResultRegistration userR = new ResultRegistration();
	    	
	    	
	    	try {
	    		
	    	
	    /**	 int keyType =  response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCredentialPublicKey().getKeyType().getValue();
	    	 long alg =  response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCredentialPublicKey().getAlgorithm().getValue();
	    	
	    	 if (keyType == 2) {
	    	 //EC key
	    		 EC2CredentialPublicKey myKey = (EC2CredentialPublicKey) response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCredentialPublicKey();
	    		  
	    		 userR.setKey(keyType, alg, Base64.getEncoder().encodeToString(myKey.getX()), Base64.getEncoder().encodeToString(myKey.getY()), null, null);
	    		 
	    		 
	    	 }else if (keyType == 3){
	    		 //RSA key
	    		 RSACredentialPublicKey myKey = (RSACredentialPublicKey) response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCredentialPublicKey();
	   		  
	    		 userR.setKey(keyType, alg, null, null, Base64.getEncoder().encodeToString(myKey.getN()), Base64.getEncoder().encodeToString(myKey.getE()));
	    		 
	    		  
	    	 }
	    	  userR.id  = Base64.getEncoder().encodeToString(response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCredentialId());
	    	  userR.signCount = response.getAttestationObject().getAuthenticatorData().getSignCount();
	    	  
	    	  printRes = jsonMapper.writeValueAsString(userR);
	    	**/
	     	Authenticator authenticator =
	     	        new AuthenticatorImpl( // You may create your own Authenticator implementation to save friendly authenticator name
	     	                response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(),
	     	                response.getAttestationObject().getAttestationStatement(),
	     	                response.getAttestationObject().getAuthenticatorData().getSignCount()
	     	        );
	     	
	     	System.out.println("authenticator: " + jsonMapper.writeValueAsString(authenticator));
	     	
	     	
	     		/**authenticator = gson.fromJson(resss, Authenticator.class);
	     	**/
	     	
	     	//Gson gson = new Gson();
	     	
	     //	System.out.println("After GSON is in: " + gson.toJson(response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData()));
	     	
	     	// return response.getAttestationObject().getAuthenticatorData();
	       return response.getAttestationObject();       
	          
	     	
	    	}
	    	catch (Exception e) {
	    		 
	    	}
	    	
	    	return null;
	    	 
	    }
	    

	
}



