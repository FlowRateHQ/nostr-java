package nostr.util;

import nostr.util.validator.HexStringValidator;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * @author squirrel
 */
public class NostrUtil {

  private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();
  private static final SecureRandom RANDOM = new SecureRandom();

  public static String bytesToHex(byte[] b) {
    char[] result = new char[b.length * 2];
    for (int i = 0; i < b.length; i++) {
      int v = b[i] & 0xFF;
      result[i * 2] = HEX_CHARS[v >>> 4];
      result[i * 2 + 1] = HEX_CHARS[v & 0x0F];
    }
    return new String(result);
  }

  public static byte[] hexToBytes(String s) {
    HexStringValidator.validateHex(s, 64);
    return parseHex(s);
  }

  public static byte[] hex128ToBytes(String s) {
    HexStringValidator.validateHex(s, 128);
    return parseHex(s);
  }

  public static byte[] nip04PubKeyHexToBytes(String s) {
    HexStringValidator.validateHex(s, 66);
    return parseHex(s);
  }

  private static byte[] parseHex(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
          + Character.digit(s.charAt(i + 1), 16));
    }
    return data;
  }

  public static byte[] bytesFromInt(int n) {
    return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(n).array();
  }

  public static byte[] bytesFromBigInteger(BigInteger n) {

    byte[] b = n.toByteArray();

    if (b.length == 32) {
      return b;
    } else if (b.length > 32) {
      return Arrays.copyOfRange(b, b.length - 32, b.length);
    } else {
      byte[] buf = new byte[32];
      System.arraycopy(b, 0, buf, buf.length - b.length, b.length);
      return buf;
    }
  }

  public static BigInteger bigIntFromBytes(byte[] b) {
    return new BigInteger(1, b);
  }

  public static byte[] sha256(byte[] b) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    return digest.digest(b);
  }

  public static byte[] xor(byte[] b0, byte[] b1) {

    if (b0.length != b1.length) {
      return null;
    }

    byte[] ret = new byte[b0.length];
    int i = 0;
    for (byte b : b0) {
      ret[i] = (byte) (b ^ b1[i]);
      i++;
    }

    return ret;
  }

  public static byte[] createRandomByteArray(int len) {
    byte[] b = new byte[len];
    RANDOM.nextBytes(b);
    return b;
  }

  public static String escapeJsonString(String jsonString) {
    return jsonString
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\b", "\\b")
        .replace("\f", "\\f")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t");
  }

  public static String unEscapeJsonString(String jsonString) {
    return jsonString
        .replace("\\\\", "\\")
        .replace("\\\"", "\"")
        .replace("\\b", "\b")
        .replace("\\f", "\f")
        .replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\t", "\t");
  }
}
