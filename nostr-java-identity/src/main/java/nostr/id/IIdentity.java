package nostr.id;

import nostr.base.ISignable;
import nostr.base.PublicKey;
import nostr.base.Signature;

public interface IIdentity {
  PublicKey getPublicKey();

  Signature sign(ISignable signable);

  byte[] computeSharedSecret(PublicKey recipientPubKey);
}
