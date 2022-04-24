package net.theunnameddude.mcclient.encryption;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

public class EncryptionUtil {

    private static SecretKey secret = new SecretKeySpec( new byte[16], "AES" );

    public static SecretKey getSecret() {
        return secret;
    }

    public static PublicKey getPubkey( byte[] pubKey ) throws GeneralSecurityException {
        return KeyFactory.getInstance( "RSA" ).generatePublic( new X509EncodedKeySpec( pubKey ) );
    }

    public static void printByteArray(byte[] array) {
        for ( String str : byteArrayToString(array) ) {
            System.out.println( str );
        }
    }

    public static byte[] encryptData( Key key, byte[] toEncrypt ) {
        try {
            Cipher cipher = Cipher.getInstance( key.getAlgorithm() );
            cipher.init( Cipher.ENCRYPT_MODE, key );
            return cipher.doFinal( toEncrypt );
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

    public static String[] byteArrayToString(byte[] array) {
        String line = "";
        ArrayList<String> result = new ArrayList<String>();
        int index = 0;
        for ( byte by : array ) {
            String byteStr = byteToString( by );
            byteStr = byteStr.length() == 4 ? byteStr : byteStr + " ";
            if ( line.isEmpty() ) {
                line = byteStr;
            } else {
                line += ", " + byteStr;
            }
            if ( index < 7 ) {
                index ++;
            } else {
                index = 0;
                result.add( line );
                line = "";
            }
        }
        return result.toArray( new String[ result.size() ] );
    }

    public static String byteToString(byte by) {
        return "0x" + Integer.toHexString( by & 0xFF );
    }
}
