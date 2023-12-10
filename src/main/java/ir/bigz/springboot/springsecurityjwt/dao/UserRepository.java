package ir.bigz.springboot.springsecurityjwt.dao;

import ir.bigz.springboot.springsecurityjwt.entity.Role;
import ir.bigz.springboot.springsecurityjwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
    User findByRole(Role role);
}
