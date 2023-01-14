package me.steadykingdev.jwttutorial.repository;

import me.steadykingdev.jwttutorial.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    @EntityGraph(attributePaths = "authorities") // Lazy조회가 아니고 Eager조회로 가져온다.
    Optional<User> findOneWithAuthoritiesByUsername(String username);
}
