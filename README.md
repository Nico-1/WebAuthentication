# WebAuthentication

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![Java CI](https://github.com/Nico-1/WebAuthentication/workflows/Java%20CI/badge.svg)
<br/>Web Authentication Compute library

Thanks to the WebAuthn standard, device based authentication is here. And it can be used either as a 2nd factor or for truly passwordless authentication system. This library can be used inside and outside of the Java environment to do "webauthn-as-a-microservice".

This application can be run on any computer or server with no need for Tomcat. The default port is 3030 but can be changed via a command line parameter. For those who wish to compile, this a Spring boot project with gradle build so all options for gradle builds are available to you. Java 8 or greater required. 

1. Compile project and run bootJar task to generate a jar file. Alternatively the included jar file in the [releases](https://github.com/Nico-1/WebAuthentication/releases) section should work for most users with no changes. It can also be deployed to Tomcat via the war file. 
2. Run the command 'java -jar webauthentication.jar'
3. For this example we'll assume you're running on localhost. If running on a different server, note the url of your machine and be sure the relevant port is open. 

A fully working prototype is [available here](https://nico-1.github.io/WebAuthentication). 

Note: As of November 2019, fully passwordless authentication requires Windows 10 (1903) or later and works on all major browsers on Windows (Edge, Firefox, Chrome). 
Safari, Firefox and Chrome on the latest Mac OS version 10.15 also support passwordless authentication with USB keys. Use of touch id as an authenticator is only available on Chrome for Mac. 
2-factor authentication is available on all major browsers on Windows (Edge, Firefox, Chrome) and Mac.
Android users can use Chrome and Firefox on Android for the same. 

Device Registration
--

Use Insomnia or any other REST API tool to make the following call:<br/>
HTTP Method: POST<br/>
URI: localhost:3030/registration<br/>
Body Payload (Full working example payload in [the samples folder](webauthentication/src/test/resources) ):
```json

{
	"id": "YcMcrYiRoynNXOsb2y0F4KmaV05YhFUUitmRq_HLu679g",
	"attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0b...",
	"clientDataJSON": "{\"challenge\":\"bmxBbUF...}",
	"verifyUser": false,
	"challenge": "nlAmABuibisJJSXfNWOsBCBfVvpVMuTAULXCtjSD",
	"hostname": "safis.accsp.org",
	"port": 8443
}
```
A successful verification should give you a json result in the format below. 
```json
{
  "authData": {
    
      "credentialId": "YcMcrYiRoynNXE6X8qULmcYasvIHLu679g...",
      "credentialPublicKey": {
        
        "-2": "2grLEKbJNp2Ma4LOmMCYiXI0/kxhEPegL5Dk7NBlyus=",
        "-3": "16GMTB/Q5QuA8qsO6hCxfUKD/sc2PfhWa61VtAI6IPw="
      }
    }
  }


```
This auth data json object contains the publickey that will be needed to verify challenges when its time to authenticate. 

Device Authentication
-

After you've registered a user, you  can now authenticate. 
Use Insomnia or any other REST API tool to make the following call: <br/>
HTTP Method: POST<br/>
URI: localhost:3030/authenticate<br/>
Body Payload (Full working example payload in test/resources folder):

```json
{
	"id": "mJ4z/MB9IYPyw3WhVUdETPLA3A3P...",
	"signature": "MEYCIQDUMGYz73SJXCegL...",
	"authenticatorData": "F3l8nOxAhyta4m8q8a6M9Qk+FrlhMDjH+L+FRVSUzTwBAAAAHg==",
	"clientDataJSON": "{\"challenge\":\"WkRhQVBD....}",
	"verifyUser": false,
	"challenge": "ZDaAPCNpCZJVOYoROsHESuuoCvGiyJHGIzLdZWcx",
	"hostname": "safis.accsp.org",
	"port": 8443,
	"lastSignCount": 0,
	"authData": {
			"credentialId": "mJ4z/MB9IYPyw3WhVUdETPLA3A3P...",
			"credentialPublicKey":"..."
			}
        }
```
A successful authentication should give a json result in the format below. 
The signCount should be saved for your next authentication:
```json
{
  "result": {
    "collectedClientData": {
      "type": "webauthn.get",
      "challenge": "WkRhQVBDTnBDWkpWT1lvUk9zSEVTdXVvQ3ZHaXlKSEdJekxkWldjeA",
      "origin": "https://safis.accsp.org:8443",
      "tokenBinding": null
    },
    "authenticatorData": "F3l8nOxAhyta4m8q8a6M9Qk+FrlhMDjH+L+FRVSUzTwBAAAAHg==",
    "authenticationExtensionsClientOutputs": null
  },
  "signCount": 30
}
```

