package guru.sfg.brewery.web.controllers;

import org.junit.Test;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.DigestUtils;

public class PasswordEncodingTests {
    static final String PASSWORD = "password";
    @Test
    public void hashingExample() {
        System.out.println(DigestUtils.md5DigestAsHex(PASSWORD.getBytes()));
        System.out.println(DigestUtils.md5DigestAsHex(PASSWORD.getBytes()));
        String salted = PASSWORD + "ThisIsMySALTVALUE";
        System.out.println(DigestUtils.md5DigestAsHex(salted.getBytes()));
    }

    @Test
    public void testNoOp() {
        PasswordEncoder noOp = NoOpPasswordEncoder.getInstance();
        System.out.println(noOp.encode(PASSWORD));
    }
}