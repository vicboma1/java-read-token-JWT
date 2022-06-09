package com.vicboma.dev.microservice.utils.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.vicboma.dev.microservice.utils.auth.service.ServiceAuthSecureImpl;
import com.vicboma.dev.microservice.domain.model.auth.Keys;
import com.vicboma.dev.microservice.infrastructure.keycloak.KeyCloakAccessTokenSecure;

import com.vicboma.dev.microservice.domain.model.auth.Certs;
import com.vicboma.dev.microservice.utils.auth.service.ServiceAuthSecureI;
import org.keycloak.RSATokenVerifier;
import org.keycloak.representations.UserInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.List;

public class AuthSecureUtils {

    private static final String BEARER = "Bearer";
    private static final String _HEAD_ = "- <[^_^]> !!!";
    private static final String ACCESO_NO_AUTORIZADO = "Acceso no autorizado " + _HEAD_;
    private static final String TOKEN_EXPIRADO = "Token expirado " + _HEAD_;
    private static final String KEY_PUBLICA_INVALIDA = "Key publica invalida ";
    private static final String JWT_OFUSCADO = "JWT ofuscado " + _HEAD_;
    private static final String ACCESO_NO_AUTORIZADO_DEBIDO_A_QUE_NO_TIENE_EL_ROL_BASE = "Acceso no autorizado debido a que no tiene el rol base -";
    private static final String RSA = "RSA";
    private static final String IDENTIFICADOR_NO_VALIDO_DEL_BEARER = "Identificador no valido del Bearer";
    private static final String PETICIÓN_NO_AUTORIZADA = "Petición no autorizada";
    private static final String PROBLEMAS_EN_LA_CONFIGURACION_DE_LOS_CERTIFICADOS_DE_KEYC_LOAK = "Problemas en la configuracion de los certificados de KeycLoak";
    private static final String BEARER_NO_INTRODUCIDO_EN_EL_HEADERS = "Bearer no introducido en el headers";

    private final Logger logger = LoggerFactory.getLogger(AuthSecureUtils.class);

    private final ServiceAuthSecureI serviceAuthSecure;

    public static AuthSecureUtils create() {
        return new AuthSecureUtils(new ServiceAuthSecureImpl(new KeyCloakAccessTokenSecure()));
    }

    AuthSecureUtils(ServiceAuthSecureI serviceAuthSecure) {
        this.serviceAuthSecure = serviceAuthSecure;
    }

    /**
     * Validate auth with 'Rol=user' by default
     * @param authorization
     * @return
     * @throws Exception
     */
    public Mono<UserInfo> getUserInfo(String authorization, String realCerts, String realmUserInfo) throws Exception {
        return getUserInfoAndValidateRol(authorization, "user", realCerts, realmUserInfo);
    }

    /**
     * User Info And Validate Rol
     * @param authorization
     * @param rol
     * @param realCerts
     * @param realmUserInfo
     * @return
     * @throws Exception
     */
    public Mono<UserInfo> getUserInfoAndValidateRol(String authorization, String rol, String realCerts, String realmUserInfo) throws Exception {
        var bearer = authorization.replace(BEARER, "").trim();
        if (bearer == null) {
            this.logger.error(BEARER_NO_INTRODUCIDO_EN_EL_HEADERS);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, BEARER_NO_INTRODUCIDO_EN_EL_HEADERS);
        } else {
            var certs = (Certs)this.serviceAuthSecure.getCerts(realCerts).block();
            if (certs.getKeys().size() < 1) {
                this.logger.error(PROBLEMAS_EN_LA_CONFIGURACION_DE_LOS_CERTIFICADOS_DE_KEYC_LOAK);
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ACCESO_NO_AUTORIZADO);
            } else {
                var verifier = RSATokenVerifier.create(bearer);
                var header = verifier.getHeader();
                Keys master = null;
                var var7 = certs.getKeys().iterator();

                while(var7.hasNext()) {
                    var key = (Keys)var7.next();
                    if (header.getKeyId().equals(key.getKid())) {
                        master = key;
                        break;
                    }
                }

                if (master == null) {
                    this.logger.error(IDENTIFICADOR_NO_VALIDO_DEL_BEARER);
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, PETICIÓN_NO_AUTORIZADA);
                } else {
                    var keyFactory = KeyFactory.getInstance(RSA);
                    var modulusBase64 = master.getN();
                    var exponentBase64 = master.getE();
                    PublicKey publicKey = null;

                    try {
                        Base64.Decoder urlDecoder = Base64.getUrlDecoder();
                        var modulus = new BigInteger(1, urlDecoder.decode(modulusBase64));
                        var publicExponent = new BigInteger(1, urlDecoder.decode(exponentBase64));
                        publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
                    } catch (InvalidKeySpecException var16) {
                        this.logger.error(KEY_PUBLICA_INVALIDA + var16.getMessage(), var16);
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ACCESO_NO_AUTORIZADO);
                    } catch (Exception var17) {
                        this.logger.error(KEY_PUBLICA_INVALIDA + var17.getMessage(), var17);
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST,ACCESO_NO_AUTORIZADO);
                    }

                    if (publicKey == null) {
                        this.logger.error(KEY_PUBLICA_INVALIDA);
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ACCESO_NO_AUTORIZADO);
                    } else {
                        var algorithm = Algorithm.RSA256((RSAPublicKey)publicKey, (RSAPrivateKey)null);
                        var jwt = JWT.decode(bearer);
                        if (jwt == null) {
                            this.logger.error(JWT_OFUSCADO);
                            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ACCESO_NO_AUTORIZADO);
                        } else {
                            algorithm.verify(jwt);
                            var roles = (List)jwt.getClaim("realm_access").asMap().get("roles");
                            if (!roles.contains(rol)) {
                                this.logger.error(ACCESO_NO_AUTORIZADO_DEBIDO_A_QUE_NO_TIENE_EL_ROL_BASE +rol+ _HEAD_);
                                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ACCESO_NO_AUTORIZADO);
                            } else {
                                Date expiryDate = jwt.getExpiresAt();
                                if (expiryDate.before(new Date())) {
                                    this.logger.error(TOKEN_EXPIRADO);
                                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, TOKEN_EXPIRADO);
                                } else {
                                    Mono<UserInfo> tokenUser = this.serviceAuthSecure.getTokenUser(bearer, realmUserInfo);
                                    return tokenUser;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
