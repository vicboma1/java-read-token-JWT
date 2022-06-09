# java-read-token-JWT


Token
```java

eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiItLS0tLS0tIiwibmFtZSI6InZpY2JvbWExIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTU4Mn0.UM5eKa7GZEDmZh-34FjA4iRXtom7pMx4x8Qd4PczzcmK1T8isYPataQm5tBJCpJ0QTG0L8HZQemWmJj-dc3iJA

eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9

{
  "alg": "HS512",
  "typ": "JWT"
}

eyJzdWIiOiItLS0tLS0tIiwibmFtZSI6InZpY2JvbWExIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTU4Mn0

{
  "sub":  "-------",
  "name": "vicboma1",
  "admin": true,
  "iat": 1516239582
}


[...]

```

Raw call

```java

Properties

keycloak.uri.user-info: https://${HOST}/auth/realms/${ID}/protocol/openid-connect/userinfo
keycloak.uri.certs: https://${HOST}/auth/realms/${ID}/protocol/openid-connect/certs


/**
 * Uso interno entre microservicios - RAW mode Rol & Token
 * 
 * @param token
 * @param rol
 * @return string | HttpStatus.NOT_FOUND
 */
  @GetMapping(value="/user/{token}/{rol}")
  @ResponseStatus(HttpStatus.OK)
  public Mono<UserInfo> getUserInfoByRol(@PathVariable String token, @PathVariable("rol") String rol) {
      try {
          return this.authSecureUtils.getUserInfoAndValidateRol(token, rol, ${keycloak.uri.certs}, ${keycloak.uri.user-info});
      }catch (Exception ex){
          logger.error(ex.getMessage());
          throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage(), ex);
      }
  }

/**
 * Ejemplo de uso para recibir llamadas desde fuera - RAW mode Rol
 * 
 * @param auth
 * @param rol
 * @return string | HttpStatus.NOT_FOUND
 */
  @GetMapping(value="/decrypt/{rol}")
  @ResponseStatus(HttpStatus.OK)
  public Mono<UserInfo> readTokenByRol(@RequestHeader("Authorization") String auth,  @PathVariable("rol") String rol) throws Exception {
      try {
          return this.authSecureUtils.getUserInfoAndValidateRol(auth, rol, ${keycloak.uri.certs}, ${keycloak.uri.user-info});
      }catch (Exception ex){
          logger.error(ex.getMessage());
          throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage(), ex);
      }
  }

/**
 * Ejemplo de uso para recibir llamadas desde fuera
 * 
 * @param auth
 * @return string | HttpStatus.NOT_FOUND
 */
 @GetMapping(value="/decrypt")
  @ResponseStatus(HttpStatus.OK)
  public Mono<UserInfo> readToken(@RequestHeader("Authorization") String auth) throws Exception {
      try {
          return this.authSecureUtils.getUserInfo(auth, ${keycloak.uri.certs}, ${keycloak.uri.user-info});
      }catch (Exception ex){
          logger.error(ex.getMessage());
          throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage(), ex);
      }
  }

```

Static Rol

```java
  @RequestMapping(value = "/anonymous", method = RequestMethod.GET)
  public ResponseEntity<String> getAnonymous() {
      return ResponseEntity.ok("Autenticación correcta, Hello Anónimo");
  }

  @RolesAllowed("user")
  @GetMapping(value = "/user")
  public ResponseEntity<String> getUser(@RequestHeader String Authorization) {
      return ResponseEntity.ok("Rol permitido, Hello User");
  }

  @RolesAllowed("des")
  @RequestMapping(value = "/des", method = RequestMethod.GET)
  public ResponseEntity<String> getDes(@RequestHeader String Authorization) {
      return ResponseEntity.ok("Hello Des");
  }

  @RolesAllowed("pre")
  @RequestMapping(value = "/pre", method = RequestMethod.GET)
  public ResponseEntity<String> getPre(@RequestHeader String Authorization) {
      return ResponseEntity.ok("Hello Pre");
  }

  @RolesAllowed({ "des", "user", "pre" })
  @RequestMapping(value = "/all-user", method = RequestMethod.GET)
  public ResponseEntity<String> getAllUser(@RequestHeader String Authorization) {
      return ResponseEntity.ok("Hello All User");
  }

```

