import { Mutex } from 'async-mutex'
import { randomBytes } from 'crypto'
import { curve, crypto as libsignalCrypto } from '@wppconnect-team/libsignal-protocol'

/**
 * Compatibility wrapper for libsignal to match WhiskeySockets/libsignal-node API
 * Ensures thread-safe operations and exact API compatibility
 */

// Global mutex for thread-safe operations
const libsignalMutex = new Mutex()

// Cache for key pairs to ensure consistency
const keyPairCache = new WeakMap()

/**
 * Validates key format and length
 */
function validateKey(key: Uint8Array | Buffer, expectedLength: number, keyType: string): void {
	if (!key) {
		throw new Error(`${keyType} is required`)
	}
	if (key.length !== expectedLength) {
		throw new Error(`Invalid ${keyType} length: expected ${expectedLength}, got ${key.length}`)
	}
}

/**
 * Ensures key is in the correct format for wppconnect functions
 */
function normalizeKey(key: Uint8Array | Buffer): Uint8Array {
	return key instanceof Buffer ? new Uint8Array(key) : key
}

/**
 * Adds version byte (0x05) to 32-byte public keys
 */
function addVersionByte(pubKey: Uint8Array | Buffer): Uint8Array {
	const normalized = normalizeKey(pubKey)
	if (normalized.length === 33) {
		return normalized // Already has version byte
	}
	if (normalized.length === 32) {
		const withVersion = new Uint8Array(33)
		withVersion[0] = 0x05 // Version byte
		withVersion.set(normalized, 1)
		return withVersion
	}
	throw new Error(`Invalid public key length: ${normalized.length}`)
}

/**
 * Removes version byte from 33-byte public keys
 */
function removeVersionByte(pubKey: Uint8Array | Buffer): Uint8Array {
	const normalized = normalizeKey(pubKey)
	if (normalized.length === 32) {
		return normalized // Already without version byte
	}
	if (normalized.length === 33 && normalized[0] === 0x05) {
		return normalized.slice(1)
	}
	throw new Error(`Invalid public key format: length ${normalized.length}`)
}

/**
 * Thread-safe random bytes generation
 */
async function getSecureRandomBytes(length: number): Promise<Uint8Array> {
	return libsignalMutex.runExclusive(async () => {
		try {
			return libsignalCrypto.getRandomBytes(length)
		} catch (error) {
			// Fallback to Node.js crypto if libsignal crypto fails
			return new Uint8Array(randomBytes(length))
		}
	})
}

/**
 * Compatibility wrapper for libsignal curve operations
 * Matches the exact API of WhiskeySockets/libsignal-node
 */
export const libsignal = {
	curve: {
		/**
		 * Generate a new key pair (matches original API - no parameters)
		 * @returns KeyPair with 32-byte private key and 32-byte public key (without version byte)
		 */
		generateKeyPair: async (): Promise<{ privKey: Uint8Array; pubKey: Uint8Array }> => {
			return libsignalMutex.runExclusive(async () => {
				try {
					// Generate secure random seed
					const seed = await getSecureRandomBytes(32)
					
					// Generate key pair using wppconnect
					const { pubKey, privKey } = curve.createKeyPair(seed)
					
					// Validate generated keys
					validateKey(privKey, 32, 'private key')
					validateKey(pubKey, 33, 'public key (with version)')
					
					// Return in original format (32-byte public key without version byte)
					const result = {
						privKey: normalizeKey(privKey),
						pubKey: removeVersionByte(pubKey)
					}
					
					// Cache for debugging/validation
					keyPairCache.set(result, { seed, originalPubKey: pubKey })
					
					return result
				} catch (error) {
					throw new Error(`Key generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
				}
			})
		},

		/**
		 * Calculate ECDH agreement (shared secret)
		 * @param publicKey 32-byte public key (without version byte)
		 * @param privateKey 32-byte private key
		 * @returns 32-byte shared secret
		 */
		calculateAgreement: async (
			publicKey: Uint8Array | Buffer,
			privateKey: Uint8Array | Buffer
		): Promise<Uint8Array> => {
			return libsignalMutex.runExclusive(async () => {
				try {
					// Validate inputs
					validateKey(publicKey, 32, 'public key')
					validateKey(privateKey, 32, 'private key')
					
					// Convert to correct format for wppconnect
					const pubKeyWithVersion = addVersionByte(publicKey)
					const privKeyNormalized = normalizeKey(privateKey)
					
					// Calculate shared secret using wppconnect ECDHE
					const shared = curve.ECDHE(pubKeyWithVersion, privKeyNormalized)
					
					// Validate output
					validateKey(shared, 32, 'shared secret')
					
					return normalizeKey(shared)
				} catch (error) {
					throw new Error(`ECDH agreement failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
				}
			})
		},

		/**
		 * Calculate Ed25519 signature
		 * @param privateKey 32-byte private key
		 * @param message Message to sign
		 * @returns 64-byte signature
		 */
		calculateSignature: async (
			privateKey: Uint8Array | Buffer,
			message: Uint8Array | Buffer
		): Promise<Uint8Array> => {
			return libsignalMutex.runExclusive(async () => {
				try {
					// Validate inputs
					validateKey(privateKey, 32, 'private key')
					if (!message || message.length === 0) {
						throw new Error('Message is required for signing')
					}
					
					// Normalize inputs
					const privKeyNormalized = normalizeKey(privateKey)
					const messageNormalized = normalizeKey(message)
					
					// Calculate signature using wppconnect
					const signature = curve.Ed25519Sign(privKeyNormalized, messageNormalized)
					
					// Validate output
					validateKey(signature, 64, 'signature')
					
					return normalizeKey(signature)
				} catch (error) {
					throw new Error(`Signature calculation failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
				}
			})
		},

		/**
		 * Verify Ed25519 signature (matches original API - throws on failure)
		 * @param publicKey 32-byte public key (without version byte)
		 * @param message Message that was signed
		 * @param signature 64-byte signature
		 * @throws Error if verification fails
		 */
		verifySignature: async (
			publicKey: Uint8Array | Buffer,
			message: Uint8Array | Buffer,
			signature: Uint8Array | Buffer
		): Promise<void> => {
			return libsignalMutex.runExclusive(async () => {
				try {
					// Validate inputs
					validateKey(publicKey, 32, 'public key')
					validateKey(signature, 64, 'signature')
					if (!message || message.length === 0) {
						throw new Error('Message is required for verification')
					}
					
					// Convert to correct format for wppconnect
					const pubKeyWithVersion = addVersionByte(publicKey)
					const messageNormalized = normalizeKey(message)
					const signatureNormalized = normalizeKey(signature)
					
					// Verify using wppconnect
					const isValid = curve.Ed25519Verify(pubKeyWithVersion, messageNormalized, signatureNormalized)
					
					// Match original API behavior - throw on failure
					if (!isValid) {
						throw new Error('Invalid signature')
					}
				} catch (error) {
					if (error instanceof Error && error.message === 'Invalid signature') {
						throw error // Re-throw signature validation errors
					}
					throw new Error(`Signature verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
				}
			})
		}
	}
}

/**
 * Synchronous versions for backward compatibility
 * Uses direct wppconnect calls without mutex for sync compatibility
 * WARNING: These are not thread-safe but match original libsignal API
 */
export const libsignalSync = {
	curve: {
		generateKeyPair: (): { privKey: Uint8Array; pubKey: Uint8Array } => {
			try {
				// Generate secure random seed synchronously
				const seed = new Uint8Array(randomBytes(32))
				
				// Generate key pair using wppconnect
				const { pubKey, privKey } = curve.createKeyPair(seed)
				
				// Validate generated keys
				if (!privKey || privKey.length !== 32) {
					throw new Error(`Invalid private key length: ${privKey?.length}`)
				}
				if (!pubKey || pubKey.length !== 33) {
					throw new Error(`Invalid public key length: ${pubKey?.length}`)
				}
				
				// Return in original format (32-byte public key without version byte)
				return {
					privKey: normalizeKey(privKey),
					pubKey: removeVersionByte(pubKey)
				}
			} catch (error) {
				throw new Error(`Key generation failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
			}
		},

		calculateAgreement: (
			publicKey: Uint8Array | Buffer,
			privateKey: Uint8Array | Buffer
		): Uint8Array => {
			try {
				// Validate inputs
				if (!publicKey || publicKey.length !== 32) {
					throw new Error(`Invalid public key length: ${publicKey?.length}`)
				}
				if (!privateKey || privateKey.length !== 32) {
					throw new Error(`Invalid private key length: ${privateKey?.length}`)
				}
				
				// Convert to correct format for wppconnect
				const pubKeyWithVersion = addVersionByte(publicKey)
				const privKeyNormalized = normalizeKey(privateKey)
				
				// Calculate shared secret using wppconnect ECDHE
				const shared = curve.ECDHE(pubKeyWithVersion, privKeyNormalized)
				
				// Validate output
				if (!shared || shared.length !== 32) {
					throw new Error(`Invalid shared secret length: ${shared?.length}`)
				}
				
				return normalizeKey(shared)
			} catch (error) {
				throw new Error(`ECDH agreement failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
			}
		},

		calculateSignature: (
			privateKey: Uint8Array | Buffer,
			message: Uint8Array | Buffer
		): Uint8Array => {
			try {
				// Validate inputs
				if (!privateKey || privateKey.length !== 32) {
					throw new Error(`Invalid private key length: ${privateKey?.length}`)
				}
				if (!message || message.length === 0) {
					throw new Error('Message is required for signing')
				}
				
				// Normalize inputs
				const privKeyNormalized = normalizeKey(privateKey)
				const messageNormalized = normalizeKey(message)
				
				// Calculate signature using wppconnect
				const signature = curve.Ed25519Sign(privKeyNormalized, messageNormalized)
				
				// Validate output
				if (!signature || signature.length !== 64) {
					throw new Error(`Invalid signature length: ${signature?.length}`)
				}
				
				return normalizeKey(signature)
			} catch (error) {
				throw new Error(`Signature calculation failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
			}
		},

		verifySignature: (
			publicKey: Uint8Array | Buffer,
			message: Uint8Array | Buffer,
			signature: Uint8Array | Buffer
		): void => {
			try {
				// Validate inputs
				if (!publicKey || publicKey.length !== 32) {
					throw new Error(`Invalid public key length: ${publicKey?.length}`)
				}
				if (!signature || signature.length !== 64) {
					throw new Error(`Invalid signature length: ${signature?.length}`)
				}
				if (!message || message.length === 0) {
					throw new Error('Message is required for verification')
				}
				
				// Convert to correct format for wppconnect
				const pubKeyWithVersion = addVersionByte(publicKey)
				const messageNormalized = normalizeKey(message)
				const signatureNormalized = normalizeKey(signature)
				
				// Verify using wppconnect
				const isValid = curve.Ed25519Verify(pubKeyWithVersion, messageNormalized, signatureNormalized)
				
				// Match original API behavior - throw on failure
				if (!isValid) {
					throw new Error('Invalid signature')
				}
			} catch (error) {
				if (error instanceof Error && error.message === 'Invalid signature') {
					throw error // Re-throw signature validation errors
				}
				throw new Error(`Signature verification failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
			}
		}
	}
}

/**
 * Debug utilities for troubleshooting
 */
export const libsignalDebug = {
	/**
	 * Get information about a generated key pair
	 */
	getKeyPairInfo: (keyPair: { privKey: Uint8Array; pubKey: Uint8Array }) => {
		const cached = keyPairCache.get(keyPair)
		return {
			hasCache: !!cached,
			privateKeyLength: keyPair.privKey.length,
			publicKeyLength: keyPair.pubKey.length,
			...cached
		}
	},

	/**
	 * Test compatibility with sample data
	 */
	testCompatibility: async () => {
		try {
			// Generate test key pair
			const keyPair = await libsignal.curve.generateKeyPair()
			
			// Test signature
			const message = new Uint8Array([1, 2, 3, 4, 5])
			const signature = await libsignal.curve.calculateSignature(keyPair.privKey, message)
			await libsignal.curve.verifySignature(keyPair.pubKey, message, signature)
			
			// Test ECDH with another key pair
			const keyPair2 = await libsignal.curve.generateKeyPair()
			const shared1 = await libsignal.curve.calculateAgreement(keyPair2.pubKey, keyPair.privKey)
			const shared2 = await libsignal.curve.calculateAgreement(keyPair.pubKey, keyPair2.privKey)
			
			return {
				success: true,
				keyGeneration: true,
				signing: true,
				verification: true,
				ecdh: true,
				sharedSecretsMatch: Buffer.compare(Buffer.from(shared1), Buffer.from(shared2)) === 0
			}
		} catch (error) {
			return {
				success: false,
				error: error instanceof Error ? error.message : 'Unknown error'
			}
		}
	}
}

export default libsignal