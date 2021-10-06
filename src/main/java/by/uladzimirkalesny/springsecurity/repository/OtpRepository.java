package by.uladzimirkalesny.springsecurity.repository;

import by.uladzimirkalesny.springsecurity.entity.Otp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OtpRepository extends JpaRepository<Otp, Long> {
    Optional<Otp> findOtpByUsername(String username);
}
