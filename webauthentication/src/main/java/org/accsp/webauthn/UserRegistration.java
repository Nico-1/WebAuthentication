package org.accsp.webauthn;

import lombok.Data;

@Data
public class UserRegistration {

	
	public String id;
	public String attestationObject;
	public String clientDataJSON;
	public boolean verifyUser;
	public String challenge;
	public String hostname;
	public int port;
	
	
}
