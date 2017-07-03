package cc.springsecurity.authentication.hash;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

import junit.framework.Assert;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;
import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordHashingTest {

    @Test
    public void encodeDecodeTest() {

        SecureRandom sr = new SecureRandom();
        byte[] seed = sr.generateSeed(1024);

        BCryptPasswordEncoder enc = new BCryptPasswordEncoder(14, new SecureRandom(seed));
        CharSequence password = "This is my password";
        String encode = enc.encode(password);

        Validate.notNull(StringUtils.isNotBlank(encode));
        Validate.isTrue(enc.matches(password, encode));

    }

    /**
     * Simulate stop / restart of jvm.
     */
    @Test
    public void encodeDecodeDifferentInstancesTest() {

        SecureRandom sr = new SecureRandom();
        byte[] seed = sr.generateSeed(1024);

        BCryptPasswordEncoder enc = new BCryptPasswordEncoder(14, new SecureRandom(seed));
        CharSequence password = "This is my password";
        String encode = enc.encode(password);

        // re set up
        sr = new SecureRandom();
        seed = sr.generateSeed(1024);
        enc = new BCryptPasswordEncoder(14, new SecureRandom(seed));

        Validate.notNull(StringUtils.isNotBlank(encode));
        Validate.isTrue(enc.matches(password, encode));

    }

    /**
     * A test method, but also a way to hash passwords to hard-code them in the app for testing.
     * 
     * @throws IOException
     */
    @Test
    public void hashAPassword() throws IOException {
        File tempDir = new File(System.getProperty("java.io.tmpdir"));
        File passwordFile = new File(tempDir, "password.to.hash");

        if (!passwordFile.exists()) {
            System.out.println("no password file at " + passwordFile.getCanonicalPath());
            return;
        }

        if (passwordFile.length() == 0L) {
            System.out.println("password file is empty");
            return;
        }

        Path path = passwordFile.toPath();

        PasswordHashing ph = new PasswordHashing();
        String storedPassword = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        String passwordHash = ph.buildPasswordHash(storedPassword);
        System.out.println(passwordHash);

        Files.write(path, new byte[0]);

        ph = new PasswordHashing();
        boolean result = ph.verifyPassword(passwordHash, storedPassword);
        Assert.assertTrue(result);
    }
}
