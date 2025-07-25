import * as nodeCrypto from 'crypto'
import { curve, crypto } from '@wppconnect-team/libsignal-protocol'

type KeyPairType = ReturnType<typeof curve.createKeyPair>

export function generateSenderKey(): Buffer {
	return nodeCrypto.randomBytes(32)
}

export function generateSenderKeyId(): number {
	return nodeCrypto.randomInt(2147483647)
}

export interface SigningKeyPair {
	public: Buffer
	private: Buffer
}

export function generateSenderSigningKey(key?: KeyPairType): SigningKeyPair {
	if (!key) {
		key = curve.createKeyPair(crypto.getRandomBytes(32))
	}

	return {
		public: Buffer.from(key.pubKey),
		private: Buffer.from(key.privKey)
	}
}
