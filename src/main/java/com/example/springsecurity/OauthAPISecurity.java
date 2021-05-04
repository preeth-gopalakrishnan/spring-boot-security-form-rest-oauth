package com.example.springsecurity;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

import com.example.springsecurity.auth.CustomUserDetails;

@Configuration()
@Order(1)
public class OauthAPISecurity extends WebSecurityConfigurerAdapter {

	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and()
		.antMatcher("/oauth/*").authorizeRequests().anyRequest().permitAll();
		
	}
	

	@Bean(name="b2capiAuthenticationEntryPoint")
	public AuthenticationEntryPoint authenticationEntryPoint() {
		BasicAuthenticationEntryPoint entryPoint = new BasicAuthenticationEntryPoint();
		entryPoint.setRealmName("b2capi realm");
		return entryPoint;
	}
	
    @Bean(name="b2capiAuthenticationProvider")
    public DaoAuthenticationProvider authenticationProvider1(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService());
        provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
        provider.setAuthoritiesMapper(authoritiesMapper());
        return provider;
    }
    
    @Bean(name="b2capiAuthoritiesMapper")
    public GrantedAuthoritiesMapper authoritiesMapper(){
        SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
        authorityMapper.setConvertToUpperCase(true);
        authorityMapper.setDefaultAuthority("USER");
        authorityMapper.setPrefix("ROLE_");
        return authorityMapper;
    }    
    
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {	
		auth.authenticationProvider(authenticationProvider1());
	}
	
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}	
	@Bean(name="b2capiUserDetailsService")
	@Override
	protected UserDetailsService userDetailsService() {
		List<UserDetails> users = new ArrayList<>();
		com.example.springsecurity.auth.User user = new com.example.springsecurity.auth.User();
		user.setId(1);
		user.setUsername("b2capiuser");
		user.setPassword("password");
		user.setRole("USER");
		CustomUserDetails details = new CustomUserDetails(user);
		users.add(details);
		return new InMemoryUserDetailsManager(users/*User.withDefaultPasswordEncoder().username("b2capiuser").password("password").roles("USER").build()*/);

	}

	@Bean(name="b2capiTokenStore")
	public TokenStore tokenStore() {
		return new InMemoryTokenStore();
	}

/*	@Bean(name="b2capiBCryptPasswordEncoder")
	public BCryptPasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}*/
	
	@EnableAuthorizationServer()
	public static class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

		static final String CLIEN_ID = "devglan-client";
		static final String CLIENT_SECRET = "{noop}devglan-secret";
		static final String PASSWORD = "password";
		static final String AUTHORIZATION_CODE = "authorization_code";
		static final String REFRESH_TOKEN = "refresh_token";
		static final String IMPLICIT = "implicit";
		static final String SCOPE_READ = "read";
		static final String SCOPE_WRITE = "write";
		static final String TRUST = "trust";
		static final int ACCESS_TOKEN_VALIDITY_SECONDS = 1*60*60;
	    static final int FREFRESH_TOKEN_VALIDITY_SECONDS = 6*60*60;
		
		@Autowired
		private TokenStore tokenStore;

		@Autowired()
		private AuthenticationManager authenticationManager;
		/*
		@Autowired()
		private UserDetailsService userDetailsService;*/

		@Override
		public void configure(ClientDetailsServiceConfigurer configurer) throws Exception {

			configurer
					.inMemory()
					.withClient(CLIEN_ID)
					.secret(CLIENT_SECRET)
					.authorizedGrantTypes(PASSWORD, AUTHORIZATION_CODE, REFRESH_TOKEN, IMPLICIT )
					.scopes(SCOPE_READ, SCOPE_WRITE, TRUST)
					.accessTokenValiditySeconds(ACCESS_TOKEN_VALIDITY_SECONDS).
					refreshTokenValiditySeconds(FREFRESH_TOKEN_VALIDITY_SECONDS);
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.tokenStore(tokenStore)/*.userDetailsService(userDetailsService);*/
					.authenticationManager(authenticationManager);
		}
	}
	
}
