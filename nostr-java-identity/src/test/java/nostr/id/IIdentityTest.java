package nostr.id;

import nostr.base.ISignable;
import nostr.base.PublicKey;
import nostr.base.Signature;
import nostr.crypto.schnorr.Schnorr;
import nostr.crypto.schnorr.SchnorrException;
import nostr.util.NostrUtil;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Tests the IIdentity interface contract using a delegating mock that wraps a real Identity.
 */
public class IIdentityTest {

  @Test
  // Verifies that an IIdentity implementation can sign and produce valid Schnorr signatures
  public void testMockIIdentitySign() throws NoSuchAlgorithmException, SchnorrException {
    String privHex = "0000000000000000000000000000000000000000000000000000000000000001";
    Identity delegate = Identity.create(privHex);

    // A mock IIdentity that delegates to a real Identity
    IIdentity mockIdentity =
        new IIdentity() {
          @Override
          public PublicKey getPublicKey() {
            return delegate.getPublicKey();
          }

          @Override
          public Signature sign(ISignable signable) {
            return delegate.sign(signable);
          }

          @Override
          public byte[] computeSharedSecret(PublicKey recipientPubKey) {
            return delegate.computeSharedSecret(recipientPubKey);
          }
        };

    final byte[] message = "test message".getBytes(StandardCharsets.UTF_8);
    ISignable signable =
        new ISignable() {
          private Signature signature;

          @Override
          public Signature getSignature() {
            return signature;
          }

          @Override
          public void setSignature(Signature signature) {
            this.signature = signature;
          }

          @Override
          public Consumer<Signature> getSignatureConsumer() {
            return this::setSignature;
          }

          @Override
          public Supplier<ByteBuffer> getByteArraySupplier() {
            return () -> ByteBuffer.wrap(message);
          }
        };

    Signature sig = mockIdentity.sign(signable);
    Assertions.assertNotNull(sig);

    byte[] msgHash = NostrUtil.sha256(message);
    boolean verified =
        Schnorr.verify(msgHash, mockIdentity.getPublicKey().getRawData(), sig.getRawData());
    Assertions.assertTrue(verified);
  }

  @Test
  // Verifies that getPublicKey via the interface returns the expected key
  public void testMockIIdentityGetPublicKey() {
    String privHex = "0000000000000000000000000000000000000000000000000000000000000001";
    Identity delegate = Identity.create(privHex);
    IIdentity iIdentity = delegate;
    PublicKey expected =
        new PublicKey("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    Assertions.assertEquals(expected, iIdentity.getPublicKey());
  }
}
