package org.accsp.webauthn;

public class ResultRegistration {

	public String id;
	
	public long signCount;
	public innerKey publicKey;
	
	public void setKey(int kty, long crv, String x, String y, String n, String e) {
		
		 publicKey = new innerKey();
		
		 if (kty == 2) {
		 publicKey.kty = "EC";
		 }
		 else if (kty == 3) {
			 publicKey.kty = "RSA";
		 }
		 if (crv == -7) {
			 publicKey.crv = "P-256";
		 }
		
		 publicKey.x = x;
		 publicKey.y = y;
		
				
	}
	
	class innerKey{
		
		public String kty;
		public String crv;
		public String x;
		public String y;
		public String n;
		public String e;
		
	}
	
}
