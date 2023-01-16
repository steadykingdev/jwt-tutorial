package me.steadykingdev.jwttutorial.config;

import lombok.RequiredArgsConstructor;
import me.steadykingdev.jwttutorial.jwt.JwtAccessDeniedHandler;
import me.steadykingdev.jwttutorial.jwt.JwtAuthenticationEntryPoint;
import me.steadykingdev.jwttutorial.jwt.JwtSecurityConfig;
import me.steadykingdev.jwttutorial.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity // 기본적인 웹 보안을 활성화
@EnableGlobalMethodSecurity(prePostEnabled = true) // @PreAuthorize를 메소드 단위로 추가하기 위해 적용
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter { // WebSecurityConfigurer를 implements하는 방법도 있음

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) { // 파비콘 관련 요청은 Spring Security 로직을 무시.
        web
                .ignoring()
                .antMatchers(
                        "/favicon.ico"
                );
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .httpBasic().disable()  // rest api 이므로 기본설정 disable, 기본설정은 비인증시 로그인폼 화면으로 리다이렉트 된다.
                .csrf().disable() // token 방식이므로 disable

                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint) // 직접만든 예외로 설정해줌.
                .accessDeniedHandler(jwtAccessDeniedHandler)           // 직접만든 예외로 설정해줌.

                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션 사용을 하지 않기때문에 stateless

                .and()
                .authorizeRequests() // HttpServletRequest를 사용하는 요청들에 대한 접근제한을 설정
                .antMatchers("/api/hello").permitAll() // 해당 api 요청은 인증없이 접근을 허용
                .antMatchers("/api/authenticate").permitAll() // 해당 api 요청은 인증없이 접근을 허용
                .antMatchers("/api/signup").permitAll() // 해당 api 요청은 인증없이 접근을 허용
                .anyRequest().authenticated() // 나머지 요청은 인증을 받아야 함.

                .and()
                .apply(new JwtSecurityConfig(tokenProvider)); // JwtFilter를 addFilterBefor로 등록한 config클래스도 적용
    }
}
