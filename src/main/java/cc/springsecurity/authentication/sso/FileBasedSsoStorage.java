package cc.springsecurity.authentication.sso;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;
import java.util.Properties;

import org.apache.commons.lang3.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import cc.springsecurity.config.CcPrincipal;

/**
 * Used to store users in a file for SSO across web applications and servers. Meant for development / testing only. Requires some sort of
 * file locking for production use.
 * 
 * @author Chris Carcel
 *
 */
public class FileBasedSsoStorage implements SsoStorage {

    private static final Logger LOG = LoggerFactory.getLogger(FileBasedSsoStorage.class);

    private static final String LOGINS_FILE_NAME = "logins";

    private final File loginsFile;

    /**
     * Store sso information in the <code>System.getProperty("java.io.tmpdir")</code> dir, {@link #LOGINS_FILE_NAME} file.
     */
    public FileBasedSsoStorage() {
        this(new File(System.getProperty("java.io.tmpdir"), LOGINS_FILE_NAME));
    }

    /**
     * Store SSO information in the given file.
     * 
     * @param file
     */
    public FileBasedSsoStorage(File file) {
        Validate.notNull(file, "file cannot be null");
        this.loginsFile = file;
    }

    /*
     * (non-Javadoc)
     * 
     * @see cc.springsecurity.authentication.sso.ISsoStorage#findUser(java.lang.String)
     */
    @Override
    public UserDetails findUser(String unid) {

        try {

            LOG.trace("Restoring from  " + loginsFile.getAbsolutePath());

            Properties p = loadProperties();

            if (!p.containsKey(unid)) {

                return null;

            } else {

                String principalAsString = p.getProperty(unid);

                Validate.notNull(principalAsString, "principalAsString cannot be null");

                CcPrincipal ccPrincipal = deserialize(principalAsString);

                return ccPrincipal;
            }

        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }

    }

    /*
     * (non-Javadoc)
     * 
     * @see cc.springsecurity.authentication.sso.ISsoStorage#storeUser(java.lang.String, org.springframework.security.core.Authentication)
     */
    @Override
    public void storeUser(String unid, Authentication auth) {
        if (auth.isAuthenticated()) {
            LOG.trace("Storing " + auth + " with unid " + unid);
            storeUserInFile(unid, auth);
        }
    }

    private void storeUserInFile(String unid, Authentication auth) {

        try {

            LOG.trace("Storing to " + loginsFile.getAbsolutePath());

            Properties p = loadProperties();

            if (p.containsKey(unid)) {
                throw new IllegalStateException("Contains the unid " + unid);
            }

            Object principal = auth.getPrincipal();

            Validate.notNull(principal, "Principal cannot be null");

            if (!(principal instanceof CcPrincipal)) {
                throw new IllegalStateException("principal is " + principal.getClass().getName() + ":" + principal);
            }

            CcPrincipal ccp = (CcPrincipal) principal;
            p.put(unid, serialize(ccp));

            storeProperties(p);

        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    protected Properties loadProperties() throws IOException, FileNotFoundException {
        Properties p = new Properties();
        if (loginsFile.exists()) {
            try (FileInputStream fin = new FileInputStream(loginsFile);) {
                p.load(fin);
            }
        }
        return p;
    }

    protected void storeProperties(Properties p) throws IOException, FileNotFoundException {
        try (FileOutputStream fout = new FileOutputStream(loginsFile);) {
            p.store(fout, "");
            fout.flush();
        }
    }

    private CcPrincipal deserialize(String s) {

        byte[] bytes = Base64.getDecoder().decode(s);

        try {
            try (ByteArrayInputStream bout = new ByteArrayInputStream(bytes); ObjectInputStream oos = new ObjectInputStream(bout);) {
                Object object = oos.readObject();

                if (!(object instanceof CcPrincipal)) {
                    throw new IllegalStateException("object " + object + " is not an instanceof CcPrincipal.");
                }

                return (CcPrincipal) object;
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String serialize(CcPrincipal p) {
        try {
            try (ByteArrayOutputStream bout = new ByteArrayOutputStream(); ObjectOutputStream oos = new ObjectOutputStream(bout);) {
                oos.writeObject(p);
                oos.flush();
                bout.flush();
                oos.close();
                bout.close();
                return Base64.getEncoder().encodeToString(bout.toByteArray());
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void removeUser(String unid) {
        try {
            Properties properties = loadProperties();
            properties.remove(unid);
            storeProperties(properties);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
