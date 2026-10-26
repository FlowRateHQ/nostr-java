package nostr.encryption;

import lombok.NonNull;
import nostr.base.PublicKey;
import nostr.crypto.nip44.EncryptedPayloads;
import nostr.id.IIdentity;
import nostr.util.NostrUtil;

public class MessageCipher44 implements MessageCipher {

  private static final int NONCE_LENGTH = 32;

  private final byte[] senderPrivateKey;
  private final byte[] recipientPublicKey;
  private final IIdentity senderIdentity;
  private final PublicKey recipientPublicKeyObj;

  public MessageCipher44(@NonNull byte[] senderPrivateKey, @NonNull byte[] recipientPublicKey) {
    this.senderPrivateKey = senderPrivateKey;
    this.recipientPublicKey = recipientPublicKey;
    this.senderIdentity = null;
    this.recipientPublicKeyObj = null;
  }

  public MessageCipher44(@NonNull IIdentity senderIdentity, @NonNull PublicKey recipientPublicKey) {
    this.senderIdentity = senderIdentity;
    this.recipientPublicKeyObj = recipientPublicKey;
    this.senderPrivateKey = null;
    this.recipientPublicKey = null;
  }

  @Override
  public String encrypt(@NonNull String message) {
    try {
      byte[] convoKey = getConversationKey();
      byte[] nonce = generateNonce();
      return EncryptedPayloads.encrypt(message, convoKey, nonce);
    } catch (Exception e) {
      throw new RuntimeException("Encryption failed: " + e.getMessage(), e);
    }
  }

  @Override
  public String decrypt(@NonNull String payload) {
    try {
      byte[] convoKey = getConversationKey();
      return EncryptedPayloads.decrypt(payload, convoKey);
    } catch (Exception e) {
      throw new RuntimeException("Decryption failed: " + e.getMessage(), e);
    }
  }

  private byte[] getConversationKey() {
    if (senderIdentity != null) {
      return senderIdentity.computeSharedSecret(recipientPublicKeyObj);
    }
    return EncryptedPayloads.getConversationKey(
        NostrUtil.bytesToHex(senderPrivateKey), "02" + NostrUtil.bytesToHex(recipientPublicKey));
  }

  private byte[] generateNonce() {
    return NostrUtil.createRandomByteArray(NONCE_LENGTH);
  }
}
