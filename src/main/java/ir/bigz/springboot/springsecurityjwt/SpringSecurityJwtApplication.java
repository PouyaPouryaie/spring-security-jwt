package ir.bigz.springboot.springsecurityjwt;

import ir.bigz.springboot.springsecurityjwt.dao.UserRepository;
import ir.bigz.springboot.springsecurityjwt.entity.Role;
import ir.bigz.springboot.springsecurityjwt.entity.User;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Objects;

@SpringBootApplication
public class SpringSecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtApplication.class, args);
	}

	@Bean
	CommandLineRunner commandLineRunner(UserRepository userRepository) {
		return args -> {
			User byRole = userRepository.findByRole(Role.ADMIN);
			if(Objects.isNull(byRole)) {
				User user = new User();

				user.setEmail("admin@gmail.com");
				user.setFirstName("admin");
				user.setLastName("admin");
				user.setRole(Role.ADMIN);
				user.setPassword(new BCryptPasswordEncoder().encode("admin"));
				userRepository.save(user);
			}
		};
	}
}
