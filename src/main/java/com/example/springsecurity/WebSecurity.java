package com.example.springsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.example.springsecurity.auth.CustomUserDetailsService;

@Configuration()
@EnableWebSecurity()
@Order(40)
public class WebSecurity extends WebSecurityConfigurerAdapter {

	@Autowired()
	private CustomUserDetailsService userdetailsService;
	
    @Bean
    public DaoAuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userdetailsService);
        provider.setPasswordEncoder(new BCryptPasswordEncoder(12));
        provider.setAuthoritiesMapper(authoritiesMapper());
        return provider;
    }
    
    @Bean
    public GrantedAuthoritiesMapper authoritiesMapper(){
        SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
        authorityMapper.setConvertToUpperCase(true);
        authorityMapper.setDefaultAuthority("USER");
        authorityMapper.setPrefix("ROLE_");
        return authorityMapper;
    }    
    
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.
			csrf().disable()
			.authorizeRequests()
			.antMatchers("/h2-console", "/*" ).permitAll()
			.antMatchers("/secured/**").authenticated()
			.and()
			.formLogin()
			.successHandler(new CustomAuthenticationSuccessHandler())
			.and()
			.logout().clearAuthentication(true).invalidateHttpSession(true);
	}


}
