package nostr.encryption;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import lombok.NonNull;
import nostr.base.PublicKey;
import nostr.crypto.nip04.EncryptedDirectMessage;
import nostr.id.Identity;
import nostr.id.IIdentity;
import nostr.util.NostrUtil;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class MessageCipher04 implements MessageCipher {

  private final byte[] senderPrivateKey;
  private final byte[] recipientPublicKey;

  public MessageCipher04(@NonNull byte[] senderPrivateKey, @NonNull byte[] recipientPublicKey) {
    this.senderPrivateKey = senderPrivateKey;
    this.recipientPublicKey = recipientPublicKey;
  }

  /**
   * Creates a NIP-04 cipher from an Identity and PublicKey.
   * Extracts raw key bytes so the correct NIP-04 ECDH shared secret is used
   * (raw x-coordinate, NOT the NIP-44 HKDF-based conversation key).
   */
  public MessageCipher04(@NonNull IIdentity senderIdentity, @NonNull PublicKey recipientPublicKey) {
    if (!(senderIdentity instanceof Identity identity)) {
      throw new IllegalArgumentException(
          "NIP-04 encryption requires an Identity instance with accessible private key");
    }
    this.senderPrivateKey = identity.getPrivateKey().getRawData();
    this.recipientPublicKey = NostrUtil.hexToBytes(recipientPublicKey.toHexString());
  }

  @Override
  public String encrypt(@NonNull String message) {
    try {
      return EncryptedDirectMessage.encrypt(message, senderPrivateKey, recipientPublicKey);
    } catch (InvalidAlgorithmParameterException
        | InvalidKeyException
        | BadPaddingException
        | NoSuchAlgorithmException
        | IllegalBlockSizeException
        | NoSuchPaddingException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public String decrypt(@NonNull String message) {
    try {
      return EncryptedDirectMessage.decryptMessage(senderPrivateKey, message, recipientPublicKey);
    } catch (InvalidAlgorithmParameterException
        | InvalidKeyException
        | BadPaddingException
        | NoSuchAlgorithmException
        | IllegalBlockSizeException
        | NoSuchPaddingException e) {
      throw new RuntimeException(e);
    }
  }
}
