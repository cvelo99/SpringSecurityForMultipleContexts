package cc.springsecurity.authentication.hash;

import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.binary.Base64;

/**
 * Thread safe class to encode strings to byte arrays and byte arrays to Strings. This class is package level access only and should be
 * access via {@link PasswordUtil}
 * 
 * @author carcelc
 * 
 */
class Coder {

    /**
     * Converts the user entered string to a byte array and calls
     * 
     * @param s
     *            a user entered string
     * @return
     */
    public String encodeToString(String s) {
        try {
            return encodeToString(s.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * Encode a byte array to a base 64 string.
     * 
     * @param b
     * @return
     */
    public String encodeToString(byte[] b) {
        return Base64.encodeBase64String(b);

    }

    /**
     * 
     * @param base64String
     * @return
     */
    public byte[] decode(String base64String) {

        return Base64.decodeBase64(base64String);
    }

}
