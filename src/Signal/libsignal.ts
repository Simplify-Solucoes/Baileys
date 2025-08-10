/* @ts-ignore */
import * as libsignal from 'libsignal'
import { LRUCache } from 'lru-cache'
import { createHash } from 'crypto'
import type { SignalAuthState, SignalKeyStoreWithTransaction } from '../Types'
import type { SignalRepository } from '../Types/Signal'
import { generateSignalPubKey } from '../Utils'
import { jidDecode } from '../WABinary'
import { LIDMappingStore } from '../Utils/lid-mapping'
import { PrivacyTokenManager } from './privacy-tokens'
import type { SenderKeyStore } from './Group/group_cipher'
import { SenderKeyName } from './Group/sender-key-name'
import { SenderKeyRecord } from './Group/sender-key-record'
import { GroupCipher, GroupSessionBuilder, SenderKeyDistributionMessage } from './Group'
import type { StorageType } from 'libsignal'

export function makeLibSignalRepository(auth: SignalAuthState): SignalRepository {
	const lidMapping = new LIDMappingStore(auth.keys as SignalKeyStoreWithTransaction)
	const storage : StorageType & SenderKeyStore = signalStorage(auth, lidMapping)
	
	// Initialize privacy token manager for session migration (following whatsmeow approach)
	const privacyTokenManager = new PrivacyTokenManager(auth.keys as SignalKeyStoreWithTransaction, lidMapping)
	
	// Link managers for cross-referencing (avoiding circular dependency)
	lidMapping.setPrivacyTokenManager(privacyTokenManager)
	
	
	// Migration deduplication cache using professional LRU library
	const migratedSessionsCache = new LRUCache<string, boolean>({
		max: 1000, // Maximum 1000 migration records
		ttl: 24 * 60 * 60 * 1000, // 24 hours TTL
		updateAgeOnGet: true, // LRU behavior: accessing refreshes the entry
		updateAgeOnHas: true, // has() calls also refresh the entry
	})
	
	// WHATSMEOW PATTERN: Buffered decryption cache to prevent message reprocessing
	// This prevents advancing the ratchet multiple times for the same ciphertext
	const decryptionCache = new LRUCache<string, Buffer>({
		max: 500, // Cache last 500 decryptions
		ttl: 5 * 60 * 1000, // 5 minutes TTL (messages shouldn't be reprocessed after this)
		updateAgeOnGet: false, // Don't update TTL on access
		updateAgeOnHas: false,
	})
	
	// WHATSMEOW PATTERN: Session recreation tracking (retry.go)
	const sessionRecreationHistory = new LRUCache<string, number>({
		max: 1000, // Track last 1000 JIDs
		ttl: 60 * 60 * 1000, // 1 hour TTL - whatsmeow uses 1 hour timeout
		updateAgeOnGet: false,
		updateAgeOnHas: false,
	})
	
	// WHATSMEOW PATTERN: Session concurrency protection for multi-device scenarios
	const sessionDecryptionLocks = new LRUCache<string, Promise<Buffer>>({
		max: 100, // Track last 100 concurrent decryptions
		ttl: 30 * 1000, // 30 seconds TTL - longer than any normal decryption
		updateAgeOnGet: false,
		updateAgeOnHas: false,
	})
	
	// Clean, simple helper functions using proper LRU cache
	const isRecentlyMigrated = (migrationKey: string): boolean => {
		return migratedSessionsCache.has(migrationKey) // Automatic TTL + LRU handling
	}
	
	const markAsMigrated = (migrationKey: string): void => {
		migratedSessionsCache.set(migrationKey, true) // Automatic eviction + TTL handling
	}
	
	// WHATSMEOW PATTERN: Session health validation
	const validateSessionExists = async (jid: string): Promise<{ exists: boolean, reason?: string }> => {
		try {
			const addr = jidToSignalProtocolAddress(jid)
			const addrStr = addr.toString()
			const session = await storage.loadSession(addrStr)
			
			if (!session) {
				return { exists: false, reason: "no session record" }
			}
			
			if (!session.haveOpenSession()) {
				return { exists: false, reason: "session record exists but no open session" }
			}
			
			return { exists: true }
		} catch (error) {
			return { exists: false, reason: `validation error: ${error}` }
		}
	}
	
	// WHATSMEOW PATTERN: Should recreate session logic (retry.go:126-137)
	const shouldRecreateSession = (jid: string, retryCount: number): { shouldRecreate: boolean, reason: string } => {
		const lastRecreationTime = sessionRecreationHistory.get(jid)
		
		// Need at least 2 retries before recreation (whatsmeow pattern)
		if (retryCount < 2) {
			return { shouldRecreate: false, reason: 'retry count below threshold' }
		}
		
		// Check if enough time passed since last recreation (1 hour)
		if (!lastRecreationTime || Date.now() - lastRecreationTime > 60 * 60 * 1000) {
			sessionRecreationHistory.set(jid, Date.now())
			return { shouldRecreate: true, reason: 'retry count > 1 and timeout expired' }
		}
		
		return { shouldRecreate: false, reason: 'recreation attempted recently' }
	}

	const repository: SignalRepository = {
		decryptGroupMessage({ group, authorJid, msg }) {
			const senderName = jidToSignalSenderKeyName(group, authorJid)
			const cipher = new GroupCipher(storage, senderName)

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				return cipher.decrypt(msg)
			})
		},

		async processSenderKeyDistributionMessage({ item, authorJid }) {
			const builder = new GroupSessionBuilder(storage)
			if (!item.groupId) {
				throw new Error('Group ID is required for sender key distribution message')
			}

			const senderName = jidToSignalSenderKeyName(item.groupId, authorJid)

			const senderMsg = new SenderKeyDistributionMessage(
				null,
				null,
				null,
				null,
				item.axolotlSenderKeyDistributionMessage
			)
			const senderNameStr = senderName.toString()
			console.log(`🔑 Processing sender key distribution for: ${senderNameStr}`)

			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { [senderNameStr]: senderKey } = await auth.keys.get('sender-key', [senderNameStr])
				console.log(`🔍 Existing sender key check: ${senderKey ? 'FOUND' : 'NOT FOUND'}`)
				
				if (!senderKey) {
					console.log(`📝 Creating new sender key record for: ${senderNameStr}`)
					await storage.storeSenderKey(senderName, new SenderKeyRecord())
				}

				console.log(`⚙️ Processing sender key message...`)
				await builder.process(senderName, senderMsg)
				
				// Verify the key was stored
				const { [senderNameStr]: verifyKey } = await auth.keys.get('sender-key', [senderNameStr])
				console.log(`✅ Sender key storage verification: ${verifyKey ? 'SUCCESS' : 'FAILED'}`)
			})
		},

		async decryptMessage({ jid, type, ciphertext }) {
			// WHATSMEOW PATTERN: Buffered decryption to prevent reprocessing same message
			// Generate cache key from jid + ciphertext hash to prevent double ratchet advancement
			const ciphertextHash = createHash('sha256').update(ciphertext).digest('hex').substring(0, 16)
			const cacheKey = `${jid}:${ciphertextHash}`
			
			// Check if this exact ciphertext was already decrypted
			const cachedResult = decryptionCache.get(cacheKey)
			if (cachedResult) {
				console.log(`🔄 Using cached decryption for ${jid} (${ciphertextHash})`)
				return cachedResult
			}
			
			// WHATSMEOW PATTERN: Concurrency protection for multi-device sessions
			// Prevent multiple concurrent decryptions from the same JID that could corrupt state
			const deviceLockKey = `${jid.split(':')[0]}` // Group by user, not device
			const existingDecryption = sessionDecryptionLocks.get(deviceLockKey)
			if (existingDecryption && type === 'pkmsg') {
				console.log(`⏳ Waiting for concurrent PreKey decryption to complete for ${jid}`)
				try {
					await existingDecryption
				} catch (error) {
					// If concurrent decryption failed, continue with our attempt
					console.warn(`⚠️ Concurrent decryption failed for ${jid}, proceeding`)
				}
			}
			
			// WHATSMEOW PATTERN: Validate session exists before decryption
			const sessionValidation = await validateSessionExists(jid)
			if (!sessionValidation.exists && type === 'msg') {
				// For regular messages (not prekey), we need an existing session
				throw new Error(`Cannot decrypt message: ${sessionValidation.reason}`)
			}
			
			// WHATSMEOW EXACT: Buffered decryption with proper transaction handling
			// This prevents session corruption during multi-device PreKey processing
			const decryptionPromise = (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				// Double-check cache inside transaction to prevent race conditions
				const innerCachedResult = decryptionCache.get(cacheKey)
				if (innerCachedResult) {
					console.log(`🔄 Using inner cached decryption for ${jid} (${ciphertextHash})`)
					return innerCachedResult
				}
				
				const addr = jidToSignalProtocolAddress(jid)
				const session = new libsignal.SessionCipher(storage, addr)
				
				let result: Buffer
				try {
					switch (type) {
						case 'pkmsg':
							console.log(`🔐 Decrypting PreKey message from ${jid}`)
							
							// CRITICAL FIX: Backup existing session before PreKey processing
							// This prevents "Closing open session in favor of incoming prekey bundle" 
							const existingSession = await storage.loadSession(addr.toString())
							let backupSessionData: any = null
							
							if (existingSession && existingSession.haveOpenSession()) {
								console.log(`💾 Backing up existing session before PreKey processing: ${jid}`)
								backupSessionData = existingSession.serialize()
							}
							
							// Process the PreKey message (this may create a new session)
							result = await session.decryptPreKeyWhisperMessage(ciphertext)
							
							// WHATSMEOW PATTERN: Restore the backed up session alongside the new PreKey session
							// This ensures multiple sessions coexist per device as intended by WhatsApp's protocol
							if (backupSessionData) {
								console.log(`🔄 Restoring backed up session alongside new PreKey session: ${jid}`)
								try {
									// Get the current session record after PreKey processing
									const currentRecord = await storage.loadSession(addr.toString())
									
									if (currentRecord) {
										// Deserialize the backup session
										const backupSession = libsignal.SessionRecord.deserialize(backupSessionData)
										
										// CRITICAL: Merge sessions by copying the backup session's states
										// into the current record. This preserves both old and new sessions.
										const backupStates = (backupSession as any).sessions || []
										const currentStates = (currentRecord as any).sessions || []
										
										// Only add backup states that aren't already present
										for (const backupState of backupStates) {
											const stateExists = currentStates.some((currentState: any) => {
												// Compare session states by their chain keys or other unique identifiers
												return JSON.stringify(currentState) === JSON.stringify(backupState)
											})
											
											if (!stateExists) {
												currentStates.push(backupState)
												console.log(`✅ Restored session state to coexist with PreKey session: ${jid}`)
											}
										}
										
										// Update the session record with merged states
										;(currentRecord as any).sessions = currentStates
										
										// Store the updated session record
										await storage.storeSession(addr.toString(), currentRecord)
										console.log(`💾 Session coexistence established for ${jid}`)
									}
								} catch (restoreError: any) {
									console.warn(`⚠️ Session restore failed for ${jid}:`, restoreError?.message || restoreError)
									// Continue with PreKey session only if restore fails
								}
							}
							break
						case 'msg':
							console.log(`🔐 Decrypting regular message from ${jid}`)
							result = await session.decryptWhisperMessage(ciphertext)
							break
						default:
							throw new Error(`Unknown message type: ${type}`)
					}
					
					// WHATSMEOW PATTERN: Only cache successful decryptions inside transaction
					// This ensures cache consistency with session state
					decryptionCache.set(cacheKey, result)
					console.log(`✅ Decryption cached for ${jid} (${ciphertextHash})`)
					
					return result
					
				} catch (decryptError: any) {
					console.error(`❌ Decryption failed for ${jid}: ${decryptError}`)
					
					// WHATSMEOW PATTERN: Clear cache on failure to prevent invalid state
					decryptionCache.delete(cacheKey)
					
					// Check if this is a session corruption issue
					if (decryptError.message?.includes('MAC verification failed') || 
					    decryptError.message?.includes('Bad message') ||
					    decryptError.message?.includes('Duplicate message')) {
						console.warn(`⚠️ Session corruption detected for ${jid}, may need recreation`)
					}
					
					throw decryptError
				}
			})
			
			// Store the decryption promise for concurrency control
			if (type === 'pkmsg') {
				sessionDecryptionLocks.set(deviceLockKey, decryptionPromise)
			}
			
			try {
				const result = await decryptionPromise
				// Clean up the lock on success
				sessionDecryptionLocks.delete(deviceLockKey)
				return result
			} catch (error) {
				// Clean up the lock on failure
				sessionDecryptionLocks.delete(deviceLockKey)
				throw error
			}
		},

		async encryptMessage({ jid, data }) {
			// WHATSMEOW EXACT LOGIC: Always prefer LID when available
			let encryptionJid = jid
			
			// OWN DEVICE OPTIMIZATION: Skip LID lookup for our own devices to prevent session corruption
			const authCreds = (auth as any).creds || auth
			const ownPhoneNumber = authCreds.me?.id?.split('@')[0]?.split(':')[0]
			const targetUser = jidDecode(jid)?.user
			
			if (ownPhoneNumber && targetUser === ownPhoneNumber) {
				console.log(`⚡ Own device optimization: Skipping LID lookup for ${jid} (own device)`)
				// Use the provided address directly - don't convert to LID
				encryptionJid = jid
			} else {
				// ENABLED: Use our LID priority system for proper message routing
				try {
					// Dynamic import for ES modules compatibility
					const { determineLIDEncryptionJid } = await import('../Utils/decode-wa-message-lid.js')
					// Create simple logger interface
					const simpleLogger = { 
						debug: console.log, 
						trace: console.log, 
						warn: console.warn,
						info: console.info,
						error: console.error,
						level: 'debug' as const,
						child: () => simpleLogger
					}
					const { encryptionJid: lidJid, shouldMigrate } = await determineLIDEncryptionJid(
						jid, undefined, repository, simpleLogger, authCreds.me?.id
					)
					
					if (lidJid !== jid) {
						console.log(`🔄 LID priority routing: ${jid} → ${lidJid}`)
						encryptionJid = lidJid
						
						// CRITICAL FIX: Only migrate if LID session doesn't exist yet
						// This prevents destroying existing sessions on every encryption
						if (shouldMigrate) {
							const lidAddr = jidToSignalProtocolAddress(lidJid)
							const existingLidSession = await storage.loadSession(lidAddr.toString())
							
							if (!existingLidSession || !existingLidSession.haveOpenSession()) {
								console.log(`🔄 Session migration required: ${jid} → ${lidJid} (LID session missing)`)
								try {
									await repository.migrateSession(jid, lidJid)
									console.log(`✅ Session migrated successfully: ${jid} → ${lidJid}`)
								} catch (migrationError: any) {
									console.error(`❌ Session migration failed: ${jid} → ${lidJid}:`, migrationError?.message || migrationError)
									// WHATSMEOW ALIGNMENT: Don't fall back to PN during encryption
									// This breaks multi-device session consistency
									console.log(`🔑 LID session required but migration failed - session establishment needed: ${lidJid}`)
									// Keep using LID address - the "No session" error will trigger proper session establishment
								}
							} else {
								console.log(`⚡ LID session already exists, skipping migration: ${jid} → ${lidJid}`)
							}
						}
					}
				} catch (error: any) {
					console.log(`⚠️ LID priority check failed for ${jid}, using original:`, error?.message || error)
					encryptionJid = jid
				}
			}
			
			console.log(`📤 Final encryption identity: ${encryptionJid}`)
			
			const addr = jidToSignalProtocolAddress(encryptionJid)
			
			// CRITICAL FIX: Don't use transaction for session operations to prevent concurrency issues
			// SESSION VALIDATION: Check session health before encryption
			const targetSession = await storage.loadSession(addr.toString())
			
			if (!targetSession || !targetSession.haveOpenSession()) {
				console.log(`⚠️ No active session at ${encryptionJid}`)
				
				// WHATSMEOW ALIGNMENT: NEVER fallback from LID to PN during encryption
				// This breaks multi-device session isolation
				
				// For LID addresses, provide more context for session establishment
				if (encryptionJid.includes('@lid')) {
					throw new Error(`No LID session available for ${encryptionJid}. Key fetching and session establishment required.`)
				} else {
					throw new Error(`No session available for ${encryptionJid}`)
				}
			} else {
				// Session exists - validate it's not corrupted
				console.log(`✅ Active session found for ${encryptionJid}`)
				
				// Additional validation: check if session has proper sessions data
				try {
					const sessions = (targetSession as any).sessions
					if (!sessions || sessions.length === 0) {
						console.warn(`⚠️ Session missing session data for ${encryptionJid}`)
					}
				} catch (validationError) {
					console.warn(`⚠️ Session validation failed for ${encryptionJid}:`, validationError)
				}
			}
			
			// Create cipher and attempt encryption WITHOUT transaction to prevent session corruption
			const cipher = new libsignal.SessionCipher(storage, addr)
			
			try {
				const { type: sigType, body } = await cipher.encrypt(data)
				const type = sigType === 3 ? 'pkmsg' : 'msg'
				return { type, ciphertext: Buffer.from(body as any, 'binary') }
			} catch (encryptionError: any) {
				console.error(`❌ libsignal encryption failed for ${encryptionJid}:`, encryptionError.message)
				console.error(`Session address: ${addr.toString()}`)
				
				// WHATSMEOW ALIGNMENT: Specific error handling patterns
				if (encryptionError.message?.includes('Assertion failed')) {
					console.error(`🚨 ASSERTION FAILED: Session corruption detected for ${encryptionJid}`)
					console.error(`🔧 This indicates invalid session state - session needs recreation`)
					throw new Error(`Session corruption detected for ${encryptionJid}: ${encryptionError.message}`)
				}
				
				if (encryptionError.message?.includes('Invalid argument')) {
					console.error(`🚨 INVALID ARGUMENT: Session parameters invalid for ${encryptionJid}`)
					throw new Error(`Invalid session parameters for ${encryptionJid}: ${encryptionError.message}`)
				}
				
				if (encryptionError.message?.includes('No session')) {
					console.error(`🚨 NO SESSION: Session does not exist for ${encryptionJid}`)
					throw new Error(`Session does not exist for ${encryptionJid}: ${encryptionError.message}`)
				}
				
				// WHATSMEOW ALIGNMENT: Don't attempt automatic session recreation during encryption
				// Session establishment should happen at the protocol level, not during encryption
				console.error(`🔧 Encryption failed - session needs to be established through proper key exchange`)
				throw encryptionError
			}
		},

		async encryptGroupMessage({ group, meId, data }) {
			const senderName = jidToSignalSenderKeyName(group, meId)
			const builder = new GroupSessionBuilder(storage)

			const senderNameStr = senderName.toString()

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { [senderNameStr]: senderKey } = await auth.keys.get('sender-key', [senderNameStr])
				if (!senderKey) {
					await storage.storeSenderKey(senderName, new SenderKeyRecord())
				}

				const senderKeyDistributionMessage = await builder.create(senderName)
				const session = new GroupCipher(storage, senderName)
				const ciphertext = await session.encrypt(data)

				return {
					ciphertext,
					senderKeyDistributionMessage: senderKeyDistributionMessage.serialize()
				}
			})
		},

		async injectE2ESession({ jid, session }) {
			const cipher = new libsignal.SessionBuilder(storage, jidToSignalProtocolAddress(jid))
			const transformedSession: any = {
				registrationId: session.registrationId,
				identityKey: Buffer.from(session.identityKey),
				signedPreKey: {
					keyId: session.signedPreKey.keyId,
					keyPair: {
						pubKey: Buffer.from(session.signedPreKey.publicKey),
						privKey: Buffer.alloc(32) // Dummy private key, not needed for outgoing
					},
					signature: session.signedPreKey.signature
				}
			}

			// Add preKey only if it exists (optional for existing sessions)
			if (session.preKey) {
				transformedSession.preKey = {
					keyId: session.preKey.keyId,
					keyPair: {
						pubKey: Buffer.from(session.preKey.publicKey),
						privKey: Buffer.alloc(32) // Dummy private key, not needed for outgoing
					}
				}
			}

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				await cipher.initOutgoing(transformedSession)
				// Note: No LID cache invalidation needed here - E2E sessions are about encryption keys,
				// not identity mappings. LID-PN relationships are independent of encryption sessions.
			})
		},

		jidToSignalProtocolAddress(jid) {
			return jidToSignalProtocolAddress(jid).toString()
		},

		/**
		 * Store LID-PN mapping (for compatibility with whatsmeow pattern)
		 */
		async storeLIDPNMapping(lid: string, pn: string) {
			await lidMapping.storeLIDPNMapping(lid, pn)
		},

		/**
		 * Get LID mapping store instance
		 */
		getLIDMappingStore() {
			return lidMapping
		},

		/**
		 * Get privacy token manager instance
		 */
		getPrivacyTokenManager() {
			return privacyTokenManager
		},

		/**
		 * WHATSMEOW PATTERN: Session health validation
		 */
		async validateSession(jid: string) {
			return validateSessionExists(jid)
		},

		/**
		 * WHATSMEOW PATTERN: Session recreation decision logic
		 */
		shouldRecreateSession(jid: string, retryCount: number) {
			return shouldRecreateSession(jid, retryCount)
		},

		/**
		 * WHATSMEOW PATTERN: Force session recreation when double ratchet becomes unstable
		 */
		async recreateSession(jid: string, reason: string = 'manual recreation') {
			const addr = jidToSignalProtocolAddress(jid)
			const addrStr = addr.toString()
			
			console.log(`🔄 Recreating session for ${jid}: ${reason}`)
			
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				try {
					// Delete existing session
					await auth.keys.set({ session: { [addrStr]: null } })
					
					// Clear decryption cache for this JID to prevent stale data
					const keysToDelete: string[] = []
					decryptionCache.forEach((_, key) => {
						if (key.startsWith(jid + ':')) {
							keysToDelete.push(key)
						}
					})
					keysToDelete.forEach(key => decryptionCache.delete(key))
					
					// Update recreation history
					sessionRecreationHistory.set(jid, Date.now())
					
					console.log(`✅ Session recreated for ${jid}`)
				} catch (error) {
					console.error(`❌ Session recreation failed for ${jid}:`, error)
					throw error
				}
			})
		},

		/**
		 * WHATSMEOW EXACT: MigratePNToLID - Device-specific ONE-WAY migration from PN to LID
		 * CRITICAL: Each device session must be migrated independently to prevent cross-device conflicts
		 */
		async migrateSession(fromJid: string, toJid: string) {
			// WHATSMEOW RULE: Only migrate PN → LID, never the reverse
			const isPN = fromJid.includes('@s.whatsapp.net')
			const isLID = toJid.includes('@lid')
			
			if (!isPN || !isLID) {
				console.log(`🚫 Invalid migration direction: ${fromJid} → ${toJid} (only PN→LID allowed)`)
				return
			}
			
			// WHATSMEOW PATTERN: Device-specific migration cache key (includes device ID)
			// This ensures each device's session is migrated independently
			const fromAddr = jidToSignalProtocolAddress(fromJid)
			const toAddr = jidToSignalProtocolAddress(toJid)
			const deviceSpecificMigrationKey = `${fromAddr.toString()}→${toAddr.toString()}`
			
			// Check if THIS SPECIFIC DEVICE was already migrated (not just the user)
			if (isRecentlyMigrated(deviceSpecificMigrationKey)) {
				console.log(`✅ Device-specific migration already completed: ${fromJid} → ${toJid}`)
				return
			}
			
			console.log(`🔄 whatsmeow device-specific MigratePNToLID: ${fromJid} → ${toJid}`)
			
			// ATOMIC MIGRATION: All operations in single transaction (whatsmeow pattern)
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				try {
					const fromAddrStr = fromAddr.toString()
					const toAddrStr = toAddr.toString()
					
					// Check if destination already has a session for this device
					const toSession = await storage.loadSession(toAddrStr)
					if (toSession && toSession.haveOpenSession()) {
						console.log(`✅ LID session already exists for device ${toJid}, skipping migration`)
						markAsMigrated(deviceSpecificMigrationKey)
						return
					}
					
					// WHATSMEOW ALIGNMENT: Actually migrate session data from PN to LID
					// This is required for multi-device session consistency
					
					const fromSession = await storage.loadSession(fromAddrStr)
					if (fromSession && fromSession.haveOpenSession()) {
						console.log(`🔄 Migrating session data: ${fromJid} → ${toJid}`)
						
						// WHATSMEOW APPROACH: Copy session data to LID address
						try {
							// Create new session at LID address with same session data
							// Use the storage interface directly like storeSession does
							await storage.storeSession(toAddrStr, fromSession)
							
							console.log(`✅ Session data migrated successfully: ${fromJid} → ${toJid}`)
							
							// Store the mapping after successful session migration
							await lidMapping.storeLIDPNMapping(toJid, fromJid)
							console.log(`🔗 LID mapping stored after session migration: ${fromJid} ↔ ${toJid}`)
							
							markAsMigrated(deviceSpecificMigrationKey)
							return
							
						} catch (migrationError) {
							console.error(`❌ Session migration failed: ${fromJid} → ${toJid}:`, migrationError)
							// Still store mapping even if session migration fails
							await lidMapping.storeLIDPNMapping(toJid, fromJid)
							throw migrationError
						}
					}
					
					// If no session exists, just store the mapping
					console.log(`ℹ️ No PN session to migrate for device: ${fromJid}`)
					await lidMapping.storeLIDPNMapping(toJid, fromJid)
					console.log(`🔗 LID mapping stored without session: ${fromJid} ↔ ${toJid}`)
					markAsMigrated(deviceSpecificMigrationKey)
					
				} catch (error) {
					console.error(`❌ Device-specific PN→LID migration failed: ${fromJid} → ${toJid}`, error)
					throw error
				}
			})
		},
		
		/**
		 * WIRE JID: Encrypt with separate wire and encryption identities
		 * Following whatsmeow's encryptMessageForDeviceAndWrap approach
		 */
		async encryptMessageWithWire({ encryptionJid, wireJid, data }) {
			// Use the existing encryptMessage for actual encryption
			const result = await repository.encryptMessage({ jid: encryptionJid, data })
			
			// Return the result with wire JID for envelope
			return {
				...result,
				wireJid
			}
		}
	}

	return repository
}

const jidToSignalProtocolAddress = (jid: string) => {
	const decoded = jidDecode(jid)!
	const { user, device, server } = decoded
	
	// Handle LID addresses by appending _1
	let signalUser = user
	if (server === 'lid') {
		signalUser = `${user}_1`
	}
	
	return new libsignal.ProtocolAddress(signalUser, device || 0)
}

const signalProtocolAddressToJid = (encodedAddress: string) => {
	// Convert signal protocol address back to JID format
	// Handle both standard and LID formats
	const parts = encodedAddress.split('.')
	let user = parts[0] || ''
	const device = parts[1]
	
	// Check for LID format (ends with _1)
	if (user.endsWith('_1')) {
		user = user.slice(0, -2) // Remove _1 suffix
		const baseJid = device && device !== '0' ? `${user}:${device}@lid` : `${user}@lid`
		return baseJid
	} else {
		// Standard PN format
		const baseJid = device && device !== '0' ? `${user}:${device}@s.whatsapp.net` : `${user}@s.whatsapp.net`
		return baseJid
	}
}

const jidToSignalSenderKeyName = (group: string, user: string): SenderKeyName => {
	return new SenderKeyName(group, jidToSignalProtocolAddress(user))
}

function signalStorage({ creds, keys }: SignalAuthState, lidMapping: LIDMappingStore): StorageType & SenderKeyStore & Record<string, any> {
	return {
		loadSession: async (id: string) => {
			try {
				console.log(`🔍 Loading session: ${id}`)
				
				// WHATSMEOW PATTERN: Device-specific LID session lookup
				let actualId = id
				if (id.includes('@s.whatsapp.net')) {
					try {
						const jid = signalProtocolAddressToJid(id)
						// CRITICAL: Use the EXACT device JID for LID lookup, not just the user part
						const lidForPN = await lidMapping.getLIDForPN(jid)
						
						if (lidForPN && lidForPN.includes('@lid')) {
							const lidId = jidToSignalProtocolAddress(lidForPN).toString()
							// Check if LID session exists for this specific device
							const { [lidId]: lidSess } = await keys.get('session', [lidId])
							if (lidSess) {
								console.log(`🔄 Device-specific session redirect: ${id} → ${lidId}`)
								actualId = lidId
							} else {
								console.log(`⚠️ LID mapping exists for ${jid} → ${lidForPN} but no session found at ${lidId}`)
							}
						}
					} catch (error) {
						console.warn(`⚠️ LID lookup failed for session ${id}:`, error)
					}
				}
				
				const { [actualId]: sess } = await keys.get('session', [actualId])
				console.log(`📦 Session result for ${actualId}: ${sess ? 'FOUND' : 'NOT FOUND'}`)
				if (sess) {
					return libsignal.SessionRecord.deserialize(sess)
				}
			} catch (e) {
				console.error('Failed to load session:', e)
				return null
			}
			return null
		},
		// TODO: Replace with libsignal.SessionRecord when type exports are added to libsignal
		storeSession: async (id: string, session: any) => {
			await keys.set({ session: { [id]: session.serialize() } })
			
			// NOTE: LID cache invalidation removed - LID mappings are identity relationships,
			// not session keys. They don't change when cryptographic sessions are updated.
			// LID cache should only be invalidated when:
			// 1. Server sends LID migration notification  
			// 2. Manual cache cleanup/maintenance
			// 3. Contact deletion
			console.log(`💾 Session stored: ${id}`)
		},
		isTrustedIdentity: async (_address: string, _identityKey: Buffer) => {
			return true
		},
		loadPreKey: async (keyId: number) => {
			const keyIdStr = keyId.toString()
			const { [keyIdStr]: key } = await keys.get('pre-key', [keyIdStr])
			if (key) {
				return {
					keyId,
					keyPair: {
						privKey: Buffer.from(key.private),
						pubKey: Buffer.from(key.public)
					}
				}
			}
			return null
		},
		removePreKey: async (keyId: number) => {
			return keys.set({ 'pre-key': { [keyId]: null } })
		},
		loadSignedPreKey: async () => {
			const key = creds.signedPreKey
			return {
				privKey: Buffer.from(key.keyPair.private),
				pubKey: Buffer.from(key.keyPair.public)
			}
		},
		loadSenderKey: async (senderKeyName: SenderKeyName) => {
			const keyId = senderKeyName.toString()
			const { [keyId]: key } = await keys.get('sender-key', [keyId])
			if (key) {
				return SenderKeyRecord.deserialize(key)
			}

			return new SenderKeyRecord()
		},
		storeSenderKey: async (senderKeyName: SenderKeyName, key: SenderKeyRecord) => {
			const keyId = senderKeyName.toString()
			console.log(`💾 Storing sender key: ${keyId}`)
			
			const serialized = key.serialize()
			console.log(`📊 Serialized sender key states: ${serialized.length} states`)
			
			const jsonStr = JSON.stringify(serialized)
			const buffer = Buffer.from(jsonStr, 'utf-8')
			
			console.log(`📦 Buffer size: ${buffer.length} bytes`)
			
			await keys.set({ 'sender-key': { [keyId]: buffer } })
			console.log(`✅ Sender key stored: ${keyId}`)
		},
		getOurRegistrationId: async () => creds.registrationId,
		getOurIdentity: async () => {
			const { signedIdentityKey } = creds
			return {
				privKey: Buffer.from(signedIdentityKey.private),
				pubKey: Buffer.from(generateSignalPubKey(signedIdentityKey.public))
			}
		},
		storeSignedPreKey: async (keyId: number, keyPair: any) => {
			// Store signed pre key - not implemented in current system
			console.warn('storeSignedPreKey not implemented:', keyId, keyPair)
		},
		removeSignedPreKey: async (keyId: number) => {
			// Remove signed pre key - not implemented in current system
			console.warn('removeSignedPreKey not implemented:', keyId)
		}
	}
}