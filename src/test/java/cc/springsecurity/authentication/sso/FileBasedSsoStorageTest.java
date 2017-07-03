package cc.springsecurity.authentication.sso;

import static java.util.stream.Collectors.toSet;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.AfterClass;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import cc.springsecurity.config.CcPrincipal;
import cc.springsecurity.config.CcPrincipalImpl;
import junit.framework.Assert;

/**
 * Tests {@link FileBasedSsoStorage}
 * 
 * @author Chris Carcel
 *
 */
public class FileBasedSsoStorageTest {

    private static final String START_STRING = "testsso_";

    /**
     * Clean up after ourselves.
     * 
     * @throws IOException
     */
    @AfterClass
    public static void after() throws IOException {
        Path tmpDirPath = Paths.get(System.getProperty("java.io.tmpdir"));
        System.out.println("Clean up " + tmpDirPath);
        Files.find(tmpDirPath, 1, (p, a) -> p.getFileName().toString().startsWith(START_STRING)).forEach(p -> {
            try {
                Files.delete(p);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Fails because the user is not authenticated.
     */
    @Test
    public void testFileNoExists1() {
        File f = new File(System.getProperty("java.io.tmpdir"), START_STRING + "noexist1");
        FileBasedSsoStorage s = new FileBasedSsoStorage(f);
        s.storeUser("unid", new UsernamePasswordAuthenticationToken(new Object(), new Object()));

        Path path = f.toPath();
        Assert.assertFalse(Files.isRegularFile(path));

    }

    /**
     * Fails because the Principal is not an {@link CcPrincipal}
     */
    @Test(expected = RuntimeException.class)
    public void testFileNoExists2() {
        File f = new File(System.getProperty("java.io.tmpdir"), START_STRING + "noexist2");
        FileBasedSsoStorage s = new FileBasedSsoStorage(f);
        s.storeUser("unid", new UsernamePasswordAuthenticationToken(new Object(), new Object(),
                Stream.of(new SimpleGrantedAuthority("Hello")).collect(toSet())));

        Path path = f.toPath();
        Assert.assertTrue(Files.isRegularFile(path));

    }

    /**
     * Fails because the Principal is not an {@link CcPrincipal}
     * 
     * @throws IOException
     */
    @Test
    public void testFileExists() throws IOException {
        File f = new File(System.getProperty("java.io.tmpdir"), START_STRING + "exist1");
        FileBasedSsoStorage s = new FileBasedSsoStorage(f);
        Set<SimpleGrantedAuthority> set = Stream.of(new SimpleGrantedAuthority("Hello")).collect(toSet());
        s.storeUser("unid", new UsernamePasswordAuthenticationToken(new CcPrincipalImpl(), new Object(), set));

        Path path = f.toPath();
        Assert.assertTrue(Files.isRegularFile(path));
        Assert.assertEquals(1, Files.readAllLines(path, StandardCharsets.UTF_8).stream().filter(l -> l.startsWith("unid"))
                .collect(Collectors.toList()).size());

    }

    /**
     * Tests finding an {@link CcPrincipal}
     * 
     * @throws IOException
     */
    @Test
    public void testFileExists2() throws IOException {
        File f = new File(System.getProperty("java.io.tmpdir"), START_STRING + "exist2");
        FileBasedSsoStorage s = new FileBasedSsoStorage(f);
        Set<SimpleGrantedAuthority> set = Stream.of(new SimpleGrantedAuthority("Hello")).collect(toSet());
        s.storeUser("unid", new UsernamePasswordAuthenticationToken(new CcPrincipalImpl(), new Object(), set));

        UserDetails findUser = s.findUser("unid");
        Assert.assertTrue(findUser instanceof CcPrincipal);

    }

}
