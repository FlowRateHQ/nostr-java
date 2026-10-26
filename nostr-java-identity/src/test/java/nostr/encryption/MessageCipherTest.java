package nostr.encryption;

import nostr.base.PrivateKey;
import nostr.base.PublicKey;
import nostr.crypto.schnorr.Schnorr;
import nostr.crypto.schnorr.SchnorrException;
import nostr.id.Identity;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MessageCipherTest {

  @Test
  // Validates that MessageCipher04 encrypts and decrypts symmetrically (byte[] constructor)
  void testMessageCipher04EncryptDecrypt() throws SchnorrException {
    byte[] alicePriv = Schnorr.generatePrivateKey();
    byte[] alicePub = Schnorr.genPubKey(alicePriv);
    byte[] bobPriv = Schnorr.generatePrivateKey();
    byte[] bobPub = Schnorr.genPubKey(bobPriv);

    MessageCipher04 alice = new MessageCipher04(alicePriv, bobPub);
    String encrypted = alice.encrypt("hello");

    MessageCipher04 bob = new MessageCipher04(bobPriv, alicePub);
    String decrypted = bob.decrypt(encrypted);
    assertEquals("hello", decrypted);
  }

  @Test
  // Validates that MessageCipher04 Identity constructor is compatible with byte[] constructor
  void testMessageCipher04IdentityCompatibility() throws SchnorrException {
    byte[] alicePriv = Schnorr.generatePrivateKey();
    byte[] alicePub = Schnorr.genPubKey(alicePriv);
    byte[] bobPriv = Schnorr.generatePrivateKey();
    byte[] bobPub = Schnorr.genPubKey(bobPriv);

    Identity aliceIdentity = Identity.create(new PrivateKey(alicePriv));
    PublicKey bobPublicKey = new PublicKey(bobPub);

    // Encrypt with Identity constructor, decrypt with byte[] constructor
    MessageCipher04 aliceWithIdentity = new MessageCipher04(aliceIdentity, bobPublicKey);
    String encrypted = aliceWithIdentity.encrypt("cross-ctor test");

    MessageCipher04 bobWithBytes = new MessageCipher04(bobPriv, alicePub);
    String decrypted = bobWithBytes.decrypt(encrypted);
    assertEquals("cross-ctor test", decrypted);
  }

  @Test
  // Validates that MessageCipher44 encrypts and decrypts symmetrically
  void testMessageCipher44EncryptDecrypt() throws SchnorrException {
    byte[] alicePriv = Schnorr.generatePrivateKey();
    byte[] alicePub = Schnorr.genPubKey(alicePriv);
    byte[] bobPriv = Schnorr.generatePrivateKey();
    byte[] bobPub = Schnorr.genPubKey(bobPriv);

    MessageCipher44 alice = new MessageCipher44(alicePriv, bobPub);
    String encrypted = alice.encrypt("hi");

    MessageCipher44 bob = new MessageCipher44(bobPriv, alicePub);
    String decrypted = bob.decrypt(encrypted);
    assertEquals("hi", decrypted);
  }
}
