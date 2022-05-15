package com.hsn.example.oauth2server;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.SneakyThrows;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.UUID;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * SecurityFilterChain-->对应一套执行拦截链
 * {@link org.springframework.security.web.FilterChainProxy#getFilters(javax.servlet.http.HttpServletRequest)}
 * 调用SecurityFilterChain的matches方法，如果对应上则返回对应的拦截器链
 * {@link org.springframework.security.web.SecurityFilterChain#matches(javax.servlet.http.HttpServletRequest)}
 * {@link org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration#httpSecurity()}
 * 注入方法中的HttpSecurity是多例的
 */
@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class AuthorizationServerConfig {


    /**
     *
     * 关闭一些csrf
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(withDefaults()).build();
    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()//指定任何经过身份验证的用户都允许使用URL。
                )
                .formLogin(withDefaults());//支持表单登录
        return http.build();
    }

    /**
     * 根据用户名加载用户信息
     */
    @Bean
    public UserDetailsService userDetailsManager() {
        return new InMemoryUserDetailsManager(Arrays.asList(
                User.builder().username("admin").password("{noop}123456").roles("user").build(),
                User.builder().username("huisunan").password("{noop}123456").roles("user").build()
        ));
    }


    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        return new InMemoryRegisteredClientRepository(Arrays.asList(
                RegisteredClient.withId("admin")
                        .clientId("admin")
                        .clientSecret("{noop}admin")
                        .redirectUri("https://pig4cloud.com")
                        //客户端的认证方法
                        //CLIENT_SECRET_POST通过post
                        //CLIENT_SECRET_BASIC http认证
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                        .authorizationGrantTypes(authorizationGrantTypes -> {
                            authorizationGrantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                            authorizationGrantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
                        })
                        .build()
        ));
    }

    @Bean
    @SneakyThrows
    public JWKSource<SecurityContext> jwkSource() {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        // @formatter:off
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public static JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().issuer("http://localhost:8080").build();
    }
}
