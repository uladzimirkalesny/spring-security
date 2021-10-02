package by.uladzimirkalesny.springsecurity.repository;

import by.uladzimirkalesny.springsecurity.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserJpaRepository extends JpaRepository<User, Long> {

    Optional<User> findUsersByUsername(String username);

}
