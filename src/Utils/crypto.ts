import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'crypto'
import { KeyHelper, curve } from '@wppconnect-team/libsignal-protocol'
import { KEY_BUNDLE_TYPE } from '../Defaults'
import type { KeyPair } from '../Types'

// insure browser & node compatibility
const { subtle } = globalThis.crypto

/** prefix version byte to the pub keys, required for some curve crypto functions */
export const generateSignalPubKey = (pubKey: Uint8Array | Buffer) =>
	pubKey.length === 33 ? pubKey : Buffer.concat([KEY_BUNDLE_TYPE, pubKey])

export const Curve = {
	generateKeyPair: (): KeyPair => {
		// Use wppconnect's proper KeyHelper to generate identity key pairs
		const keyPair = KeyHelper.generateIdentityKeyPair()
		return {
			private: Buffer.from(keyPair.privKey),
			public: Buffer.from(keyPair.pubKey) // Keep full key with version byte for consistent handling
		}
	},
	sharedKey: (privateKey: Uint8Array, publicKey: Uint8Array) => {
		// Ensure publicKey has version byte for ECDHE
		const pubKeyWithVersion = publicKey.length === 32 ? 
			Buffer.concat([KEY_BUNDLE_TYPE, publicKey]) : publicKey
		const shared = curve.ECDHE(pubKeyWithVersion, privateKey)
		return Buffer.from(shared)
	},
	sign: (privateKey: Uint8Array, buf: Uint8Array) => {
		const signature = curve.Ed25519Sign(privateKey, buf)
		return Buffer.from(signature)
	},
	verify: (pubKey: Uint8Array, message: Uint8Array, signature: Uint8Array) => {
		try {
			// Ensure pubKey has version byte for verification
			const pubKeyWithVersion = pubKey.length === 32 ? 
				Buffer.concat([KEY_BUNDLE_TYPE, pubKey]) : pubKey
			return curve.Ed25519Verify(pubKeyWithVersion, message, signature)
		} catch (error) {
			return false
		}
	}
}

// Async versions for backward compatibility (same as sync since wppconnect operations are sync)
export const CurveAsync = {
	generateKeyPair: async (): Promise<KeyPair> => {
		return Curve.generateKeyPair()
	},
	sharedKey: async (privateKey: Uint8Array, publicKey: Uint8Array): Promise<Buffer> => {
		return Curve.sharedKey(privateKey, publicKey)
	},
	sign: async (privateKey: Uint8Array, buf: Uint8Array): Promise<Buffer> => {
		return Curve.sign(privateKey, buf)
	},
	verify: async (pubKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> => {
		return Curve.verify(pubKey, message, signature)
	}
}

export const signedKeyPair = (identityKeyPair: KeyPair, keyId: number) => {
	// Generate prekey using the direct approach (like original libsignal)
	const preKey = Curve.generateKeyPair()
	
	// For signing, we need the raw 32-byte public key (without version byte)
	const preKeyPublicRaw = preKey.public.length === 33 ? preKey.public.slice(1) : preKey.public
	const identityPublicRaw = identityKeyPair.public.length === 33 ? identityKeyPair.public.slice(1) : identityKeyPair.public
	
	// Sign the raw 32-byte public key directly with identity private key
	const signature = Curve.sign(identityKeyPair.private, preKeyPublicRaw)
	
	// Verify our signature using the raw public keys
	const isValidSig = Curve.verify(identityPublicRaw, preKeyPublicRaw, signature)
	
	console.log('signedKeyPair: debug info', {
		keyId,
		preKeyPublicLength: preKey.public.length,
		preKeyPublicRawLength: preKeyPublicRaw.length,
		identityPublicLength: identityKeyPair.public.length,
		identityPublicRawLength: identityPublicRaw.length,
		signatureLength: signature.length,
		signatureValid: isValidSig,
		preKeyPublicHex: Buffer.from(preKeyPublicRaw).toString('hex').substring(0, 16) + '...',
		signatureHex: Buffer.from(signature).toString('hex').substring(0, 16) + '...',
		identityKeyHex: Buffer.from(identityPublicRaw).toString('hex').substring(0, 16) + '...'
	})

	if (!isValidSig) {
		throw new Error('Generated signature is invalid - signature verification failed')
	}

	return { 
		keyPair: { 
			private: preKey.private, 
			public: preKeyPublicRaw // Return raw 32-byte public key for WhatsApp compatibility
		}, 
		signature: Buffer.from(signature), 
		keyId 
	}
}

const GCM_TAG_LENGTH = 128 >> 3

/**
 * encrypt AES 256 GCM;
 * where the tag tag is suffixed to the ciphertext
 * */
export function aesEncryptGCM(plaintext: Uint8Array, key: Uint8Array, iv: Uint8Array, additionalData: Uint8Array) {
	const cipher = createCipheriv('aes-256-gcm', key, iv)
	cipher.setAAD(additionalData)
	return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
}

/**
 * decrypt AES 256 GCM;
 * where the auth tag is suffixed to the ciphertext
 * */
export function aesDecryptGCM(ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array, additionalData: Uint8Array) {
	const decipher = createDecipheriv('aes-256-gcm', key, iv)
	// decrypt additional adata
	const enc = ciphertext.slice(0, ciphertext.length - GCM_TAG_LENGTH)
	const tag = ciphertext.slice(ciphertext.length - GCM_TAG_LENGTH)
	// set additional data
	decipher.setAAD(additionalData)
	decipher.setAuthTag(tag)

	return Buffer.concat([decipher.update(enc), decipher.final()])
}

export function aesEncryptCTR(plaintext: Uint8Array, key: Uint8Array, iv: Uint8Array) {
	const cipher = createCipheriv('aes-256-ctr', key, iv)
	return Buffer.concat([cipher.update(plaintext), cipher.final()])
}

export function aesDecryptCTR(ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array) {
	const decipher = createDecipheriv('aes-256-ctr', key, iv)
	return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

/** decrypt AES 256 CBC; where the IV is prefixed to the buffer */
export function aesDecrypt(buffer: Buffer, key: Buffer) {
	return aesDecryptWithIV(buffer.slice(16, buffer.length), key, buffer.slice(0, 16))
}

/** decrypt AES 256 CBC */
export function aesDecryptWithIV(buffer: Buffer, key: Buffer, IV: Buffer) {
	const aes = createDecipheriv('aes-256-cbc', key, IV)
	return Buffer.concat([aes.update(buffer), aes.final()])
}

// encrypt AES 256 CBC; where a random IV is prefixed to the buffer
export function aesEncrypt(buffer: Buffer | Uint8Array, key: Buffer) {
	const IV = randomBytes(16)
	const aes = createCipheriv('aes-256-cbc', key, IV)
	return Buffer.concat([IV, aes.update(buffer), aes.final()]) // prefix IV to the buffer
}

// encrypt AES 256 CBC with a given IV
export function aesEncrypWithIV(buffer: Buffer, key: Buffer, IV: Buffer) {
	const aes = createCipheriv('aes-256-cbc', key, IV)
	return Buffer.concat([aes.update(buffer), aes.final()]) // prefix IV to the buffer
}

// sign HMAC using SHA 256
export function hmacSign(
	buffer: Buffer | Uint8Array,
	key: Buffer | Uint8Array,
	variant: 'sha256' | 'sha512' = 'sha256'
) {
	return createHmac(variant, key).update(buffer).digest()
}

export function sha256(buffer: Buffer) {
	return createHash('sha256').update(buffer).digest()
}

export function md5(buffer: Buffer) {
	return createHash('md5').update(buffer).digest()
}

// HKDF key expansion
export async function hkdf(
	buffer: Uint8Array | Buffer,
	expandedLength: number,
	info: { salt?: Buffer; info?: string }
): Promise<Buffer> {
	// Ensure we have a Uint8Array for the key material
	const inputKeyMaterial = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)

	// Set default values if not provided
	const salt = info.salt ? new Uint8Array(info.salt) : new Uint8Array(0)
	const infoBytes = info.info ? new TextEncoder().encode(info.info) : new Uint8Array(0)

	// Import the input key material
	const importedKey = await subtle.importKey('raw', inputKeyMaterial, { name: 'HKDF' }, false, ['deriveBits'])

	// Derive bits using HKDF
	const derivedBits = await subtle.deriveBits(
		{
			name: 'HKDF',
			hash: 'SHA-256',
			salt: salt,
			info: infoBytes
		},
		importedKey,
		expandedLength * 8 // Convert bytes to bits
	)

	return Buffer.from(derivedBits)
}

export async function derivePairingCodeKey(pairingCode: string, salt: Buffer): Promise<Buffer> {
	// Convert inputs to formats Web Crypto API can work with
	const encoder = new TextEncoder()
	const pairingCodeBuffer = encoder.encode(pairingCode)
	const saltBuffer = salt instanceof Uint8Array ? salt : new Uint8Array(salt)

	// Import the pairing code as key material
	const keyMaterial = await subtle.importKey('raw', pairingCodeBuffer, { name: 'PBKDF2' }, false, ['deriveBits'])

	// Derive bits using PBKDF2 with the same parameters
	// 2 << 16 = 131,072 iterations
	const derivedBits = await subtle.deriveBits(
		{
			name: 'PBKDF2',
			salt: saltBuffer,
			iterations: 2 << 16,
			hash: 'SHA-256'
		},
		keyMaterial,
		32 * 8 // 32 bytes * 8 = 256 bits
	)

	return Buffer.from(derivedBits)
}
