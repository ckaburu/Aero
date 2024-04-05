package info.gezielcarvalho.aerojudic.auth;

import info.gezielcarvalho.aerojudic.config.JwtService;
import info.gezielcarvalho.aerojudic.user.Role;
import info.gezielcarvalho.aerojudic.user.User;
import info.gezielcarvalho.aerojudic.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.hibernate.annotations.NotFound;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@SuppressWarnings("unused")
@Service
@RequiredArgsConstructor
public class AuthenticationService {

        private final UserRepository repository;
        private final PasswordEncoder passwordEncoder;
        private final JwtService jwtService;
        private final AuthenticationManager authenticationManager;
        @SuppressWarnings("static-access")
        public AuthenticationResponse register(RegisterRequest request) {
            var user = User.builder()
                    .email(request.getEmail())
                    .firstname(request.getFirstname())
                    .lastname(request.getLastname())
                    .role(Role.ADMIN)
                    .password(passwordEncoder.encode(request.getPassword()))
                    .build();
            repository.save(user);
            var token = jwtService.generateToken(user);
            return new AuthenticationResponse().builder()
                    .token(token)
                    .build();
        }

        @SuppressWarnings("static-access")
        public AuthenticationResponse authenticate(AuthenticationRequest request) {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(), request.getPassword()));
            var user = repository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new RuntimeException("User not found"));
            var token = jwtService.generateToken(user);
            return new AuthenticationResponse().builder()
                    .token(token)
                    .build();
        }
}
