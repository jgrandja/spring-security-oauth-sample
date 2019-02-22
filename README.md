# spring-security-oauth-sample

This sample demonstrates how to set a custom 
`AuthenticationEntryPoint` on `BasicAuthenticationFilter`, 
which is used by the Authorization Server to authenticate clients.

**NOTE:** The code in this sample is a temporary workaround until [Issue #501](https://github.com/spring-projects/spring-security-oauth/issues/501) is resolved.

* Build the sample -> `./gradlew clean build`
* Run Authorization Server -> `./gradlew -b auth-server/build.gradle bootRun`
* Obtain access token using `client_credentials` grant -> `curl --user client-1234:secret -d "grant_type=client_credentials&scope=scope1" -X POST http://localhost:8090/oauth/token`
* Trigger callback to custom `AuthenticationEntryPoint` with failed client authentication -> `curl --user client-1234:invalid-secret -d "grant_type=client_credentials&scope=scope1" -X POST http://localhost:8090/oauth/token`
