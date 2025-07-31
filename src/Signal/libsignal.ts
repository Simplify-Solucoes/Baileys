/* @ts-ignore */
import * as libsignal from 'libsignal'
import type { SignalAuthState, SignalKeyStoreWithTransaction } from '../Types'
import type { SignalRepository } from '../Types/Signal'
import type { StorageType } from 'libsignal'
import { generateSignalPubKey } from '../Utils'
import { jidDecode } from '../WABinary'
import { SenderKeyName } from './Group/sender-key-name'
import { SenderKeyRecord } from './Group/sender-key-record'
import { GroupCipher, GroupSessionBuilder, SenderKeyDistributionMessage } from './Group'
import type { SenderKeyStore } from './Group/group_cipher'

export function makeLibSignalRepository(auth: SignalAuthState): SignalRepository {
	const storage : StorageType & SenderKeyStore = signalStorage(auth)
	return {
		decryptGroupMessage({ group, authorJid, msg }) {
			const senderName = jidToSignalSenderKeyName(group, authorJid)
			const cipher = new GroupCipher(storage, senderName)

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				// First, check if we have a valid session for the author (for individual messages)
				const authorAddress = jidToSignalProtocolAddress(authorJid)
				const authorSession = await storage.loadSession(authorAddress.toString())
				
				console.debug(`[decryptGroupMessage] Checking session status for ${authorJid}:`, {
					hasSession: !!authorSession,
					hasOpenSession: authorSession ? authorSession.haveOpenSession() : false,
					group,
					authorJid
				})
				
				// Check if we have a valid sender key record before attempting decryption
				const record = await storage.loadSenderKey(senderName)
				if (record.isEmpty()) {
					console.debug(`[decryptGroupMessage] Sender key record is empty for ${senderName.toString()}`)
					// Check if this is a message from our own device (same user, different device)
					const { user: authorUser } = jidDecode(authorJid)!
					const meId = (auth.creds as any).me?.id
					const { user: meUser } = meId ? jidDecode(meId)! : { user: null }
					
					if (authorUser === meUser && meId) {
						console.debug(`Message from our own device ${authorJid} - attempting cross-device sender key lookup`)
						
						// Try to find sender keys from any of our own devices for this group
						// Use more robust matching that handles device ID variations
						const allSenderKeys = await auth.keys.get('sender-key', [])
						
						console.debug(`[crossDeviceSync] Looking for sender keys for user: ${meUser} in group: ${group}`)
						console.debug(`[crossDeviceSync] Available sender keys:`, Object.keys(allSenderKeys || {}))  
						console.debug(`[crossDeviceSync] Total sender keys count:`, Object.keys(allSenderKeys || {}).length)
						
						// Also check for any sender keys in this group regardless of device
						const groupKeys = Object.keys(allSenderKeys || {}).filter(key => key.startsWith(`${group}::`))
						console.debug(`[crossDeviceSync] All sender keys in group ${group}:`, groupKeys)
						
						// Look for any sender key from our own devices in this group using robust matching
						// Handle both formatted user IDs (user:device) and simple user IDs
						const normalizedMeUser = meUser.split(':')[0] // Get base user ID without device
						const ownDeviceKeys = Object.keys(allSenderKeys || {}).filter(key => {
							// Parse key format: group::user::device or group::user:device::device
							const keyParts = key.split('::')
							if (keyParts.length !== 3) return false
							
							const [keyGroup, keyUser] = keyParts
							if (!keyUser) return false // Ensure keyUser is defined
							const normalizedKeyUser = keyUser.split(':')[0] // Get base user ID
							
							return keyGroup === group && normalizedKeyUser === normalizedMeUser
						})
						
						if (ownDeviceKeys.length > 0) {
							console.debug(`Found ${ownDeviceKeys.length} sender keys from our own devices:`, ownDeviceKeys)
							
							// Try to copy sender key from our own device with enhanced logic
							for (const sourceKeyName of ownDeviceKeys) {
								try {
									console.debug(`Attempting to copy sender key from ${sourceKeyName} to ${senderName.toString()}`)
									
									const { [sourceKeyName]: sourceKeyData } = await auth.keys.get('sender-key', [sourceKeyName])
									
									if (sourceKeyData) {
										// Parse and validate the source key data
										let parsedKeyData
										if (sourceKeyData instanceof Buffer) {
											parsedKeyData = JSON.parse(sourceKeyData.toString())
										} else {
											parsedKeyData = sourceKeyData
										}
										
										console.debug(`Source key data structure:`, {
											sourceKeyName,
											hasKeyStates: !!parsedKeyData.keyStates,
											keyStatesCount: parsedKeyData.keyStates?.length || 0,
											hasVersion: !!parsedKeyData.version
										})
										
										// Enhanced validation - check for both keyStates and valid structure
										if (parsedKeyData.keyStates && parsedKeyData.keyStates.length > 0) {
											// Validate that at least one key state has a valid key
											const hasValidKeyState = parsedKeyData.keyStates.some((keyState: any) => 
												keyState && keyState.senderChainKey && keyState.senderMessageKeys
											)
											
											if (!hasValidKeyState) {
												console.warn(`Source key ${sourceKeyName} has empty key states`)
												continue
											}
											
											// Copy the sender key data to the new sender name
											const targetKeyData = Buffer.from(JSON.stringify(parsedKeyData))
											await auth.keys.set({ 
												'sender-key': { 
													[senderName.toString()]: targetKeyData 
												} 
											})
											
											console.info(`Successfully copied sender key from ${sourceKeyName} to ${senderName.toString()}`)
											
											// Reload the record after copying to verify it works
											const newRecord = await storage.loadSenderKey(senderName)
											if (!newRecord.isEmpty()) {
												console.info(`Cross-device sender key copy successful - attempting decryption`)
												try {
													const decryptedMsg = await cipher.decrypt(msg)
													console.info(`Cross-device decryption successful for ${senderName.toString()}`)
													return decryptedMsg
												} catch (decryptError) {
													console.error(`Decryption failed even after key copy:`, decryptError)
													// Remove the bad key copy and continue to next
													await auth.keys.set({ 'sender-key': { [senderName.toString()]: null } })
													continue
												}
											} else {
												console.warn(`Copied sender key but record is still empty for ${senderName.toString()}`)
											}
										} else {
											console.warn(`Source key ${sourceKeyName} has invalid or empty key states`)
										}
									} else {
										console.warn(`No key data found for source key ${sourceKeyName}`)
									}
								} catch (copyError) {
									console.error(`Failed to copy sender key from ${sourceKeyName}:`, copyError)
									// Continue to next available key
								}
							}
							
							// If we reach here, cross-device key copying failed
							console.warn(`All cross-device key copying attempts failed for ${senderName.toString()}`)
						}
					}
					
					console.debug(`Sender key record is empty for ${senderName.toString()} - triggering retry`)
					throw new Error(`No sender key found for ${senderName.toString()}`)
				}
				
				console.debug(`[decryptGroupMessage] Attempting to decrypt group message with valid sender key record`)
				
				try {
					return await cipher.decrypt(msg)
				} catch (decryptError: any) {
					console.error(`[decryptGroupMessage] Decryption failed for ${authorJid} in group ${group}:`, {
						error: decryptError.message,
						hasSession: !!authorSession,
						hasOpenSession: authorSession ? authorSession.haveOpenSession() : false,
						senderKeyRecordEmpty: record.isEmpty()
					})
					
					// Re-throw with more context
					throw new Error(`Group message decryption failed: ${decryptError.message} (hasSession: ${!!authorSession}, hasOpenSession: ${authorSession ? authorSession.haveOpenSession() : false})`)
				}
			})
		},

		async processSenderKeyDistributionMessage({ item, authorJid }) {
			const builder = new GroupSessionBuilder(storage)
			console.debug(`[processSenderKeyDistributionMessage] Processing from ${authorJid}`, {
				hasGroupId: !!item.groupId,
				groupId: item.groupId,
				hasAxolotlMessage: !!item.axolotlSenderKeyDistributionMessage
			})
			
			if (!item.groupId) {
				console.error(`[processSenderKeyDistributionMessage] Missing groupId for sender key from ${authorJid}:`, item)
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

			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { [senderNameStr]: senderKey } = await auth.keys.get('sender-key', [senderNameStr])
				if (!senderKey) {
					await storage.storeSenderKey(senderName, new SenderKeyRecord())
				}

				await builder.process(senderName, senderMsg)
			})
		},
		async decryptMessage({ jid, type, ciphertext }) {
			const addr = jidToSignalProtocolAddress(jid)
			const session = new libsignal.SessionCipher(storage, addr)

			// Use transaction to ensure atomicityAdd commentMore actions
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				let result: Buffer
				switch (type) {
					case 'pkmsg':
						result = await session.decryptPreKeyWhisperMessage(ciphertext)
						break
					case 'msg':
						result = await session.decryptWhisperMessage(ciphertext)
						break
				}

				return result
			})
		},
		async encryptMessage({ jid, data }) {
			const addr = jidToSignalProtocolAddress(jid)
			const cipher = new libsignal.SessionCipher(storage, addr)
			console.debug(`[encryptMessage] Encrypting for JID: ${jid}, Address: ${addr.toString()}`)

			// Use transaction to ensure atomicityAdd commentMore actions
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { type: sigType, body } = await cipher.encrypt(data)
				const type = sigType === 3 ? 'pkmsg' : 'msg'
				return { type, ciphertext: Buffer.from(body as any, 'binary') }
			})
		},
		async encryptGroupMessage({ group, meId, data }) {
			const senderName = jidToSignalSenderKeyName(group, meId)
			const builder = new GroupSessionBuilder(storage)

			const senderNameStr = senderName.toString()
			console.log(`[encryptGroupMessage] Starting encryption for group: ${group}, sender: ${senderNameStr}`)
			console.log(`[encryptGroupMessage] meId: ${meId}`)

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { [senderNameStr]: senderKey } = await auth.keys.get('sender-key', [senderNameStr])
				console.log(`[encryptGroupMessage] Existing sender key found: ${!!senderKey}`)
				
				if (!senderKey) {
					console.log(`[encryptGroupMessage] Creating new sender key record for ${senderNameStr}`)
					const newRecord = new SenderKeyRecord()
					console.log(`[encryptGroupMessage] New record isEmpty: ${newRecord.isEmpty()}`)
					await storage.storeSenderKey(senderName, newRecord)
					console.log(`[encryptGroupMessage] Stored new sender key record`)
				}

				console.log(`[encryptGroupMessage] About to create sender key distribution message`)
				const senderKeyDistributionMessage = await builder.create(senderName)
				console.log(`[encryptGroupMessage] Created sender key distribution message, size: ${senderKeyDistributionMessage.serialize().length} bytes`)
				
				console.log(`[encryptGroupMessage] About to encrypt data`)
				const session = new GroupCipher(storage, senderName)
				const ciphertext = await session.encrypt(data)
				console.log(`[encryptGroupMessage] Encrypted message, ciphertext size: ${ciphertext.length} bytes`)

				// Verify the sender key was properly stored after encryption
				const { [senderNameStr]: finalSenderKey } = await auth.keys.get('sender-key', [senderNameStr])
				console.log(`[encryptGroupMessage] Final verification - sender key exists: ${!!finalSenderKey}`)
				
				if (finalSenderKey) {
					const record = SenderKeyRecord.deserialize(finalSenderKey)
					console.log(`[encryptGroupMessage] Final sender key record isEmpty: ${record.isEmpty()}`)
				}

				return {
					ciphertext,
					senderKeyDistributionMessage: senderKeyDistributionMessage.serialize()
				}
			})
		},
		async injectE2ESession({ jid, session }) {
			const cipher = new libsignal.SessionBuilder(storage, jidToSignalProtocolAddress(jid))

			// Transform session to match libsignal expected type
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
			})
		},
		jidToSignalProtocolAddress(jid) {
			return jidToSignalProtocolAddress(jid).toString()
		}
	}
}

const jidToSignalProtocolAddress = (jid: string) => {
	const { user, device } = jidDecode(jid)!
	return new libsignal.ProtocolAddress(user, device || 0)
}

const jidToSignalSenderKeyName = (group: string, user: string): SenderKeyName => {
	return new SenderKeyName(group, jidToSignalProtocolAddress(user))
}

function signalStorage({ creds, keys }: SignalAuthState): StorageType & SenderKeyStore & Record<string, any> {
	return {
		loadSession: async (id: string) => {
			console.debug(`[loadSession] Attempting to load session for ID: ${id}`)
			const { [id]: sess } = await keys.get('session', [id])
			if (sess) {
				try {
					// Handle both Buffer (new format) and direct object (existing format)
					let sessionData
					if (sess instanceof Buffer) {
						// Parse JSON from Buffer (current storage format)
						sessionData = JSON.parse(sess.toString())
					} else {
						// Direct object format (legacy or direct storage)
						sessionData = sess
					}
					
					// Ensure session data has the proper structure required by libsignal
					if (!sessionData.version) {
						console.debug(`Adding missing version to session ${id}`)
						sessionData.version = 'v1'
					}
					if (!sessionData._sessions) {
						console.debug(`Session ${id} has no _sessions field, initializing empty`)
						sessionData._sessions = {}
					}
					
					// sessionData should now be a SerializedSessionRecordData object
					const sessionRecord = libsignal.SessionRecord.deserialize(sessionData)
					console.debug(`Successfully loaded session for ${id}`, { hasOpenSession: sessionRecord.haveOpenSession() })
					return sessionRecord
				} catch (error) {
					console.error('Failed to deserialize session:', id, error, { sessionType: typeof sess, isBuffer: sess instanceof Buffer })
					// Return null so a new session can be created
					return null
				}
			}
			console.debug(`[loadSession] No session found for ID: ${id}`)
			return null
		},
		storeSession: async (id: string, session: libsignal.SessionRecord) => {
			try {
				const serialized = session.serialize()
				// Store the serialized session data as JSON in Buffer format
				// This maintains consistency with other key storage in Baileys
				const buffer = Buffer.from(JSON.stringify(serialized))
				await keys.set({ session: { [id]: buffer } })
				console.debug(`Successfully stored session for ${id}`, { 
					hasOpenSession: session.haveOpenSession(),
					sessionCount: Object.keys(serialized._sessions || {}).length 
				})
			} catch (error) {
				console.error(`Failed to store session for ${id}:`, error)
				throw error
			}
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
			throw new Error(`PreKey ${keyId} not found`)
		},
		removePreKey: async (keyId: number) => {
			return keys.set({ 'pre-key': { [keyId]: null } })
		},
		loadSignedPreKey: async (_keyId: number) => {
			const key = creds.signedPreKey
			return {
				privKey: Buffer.from(key.keyPair.private),
				pubKey: Buffer.from(key.keyPair.public)
			}
		},
		loadSenderKey: async (senderKeyName: SenderKeyName) => {
			const keyId = senderKeyName.toString()
			console.debug(`[loadSenderKey] Loading sender key: ${keyId}`)
			const { [keyId]: key } = await keys.get('sender-key', [keyId])
			if (key) {
				console.debug(`[loadSenderKey] Found sender key: ${keyId}`)
				const record = SenderKeyRecord.deserialize(key)
				console.debug(`[loadSenderKey] Record isEmpty: ${record.isEmpty()}`)
				return record
			}

			console.debug(`[loadSenderKey] No sender key found for: ${keyId}, returning empty record`)
			// Return empty record to satisfy interface - we'll check validity in decryption
			return new SenderKeyRecord()
		},
		storeSenderKey: async (senderKeyName: SenderKeyName, key: SenderKeyRecord) => {
			const keyId = senderKeyName.toString()
			const serialized = JSON.stringify(key.serialize())
			console.debug(`[storeSenderKey] Storing sender key: ${keyId}`)
			console.debug(`[storeSenderKey] Key data:`, {
				keyId,
				serializedSize: serialized.length,
				isEmpty: key.isEmpty()
			})
			await keys.set({ 'sender-key': { [keyId]: Buffer.from(serialized, 'utf-8') } })
			
			// Verify the key was stored by immediately trying to load it
			const { [keyId]: storedKey } = await keys.get('sender-key', [keyId])
			console.debug(`[storeSenderKey] Verification - stored key exists:`, !!storedKey)
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
