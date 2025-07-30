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
				// Check if we have a valid sender key record before attempting decryption
				const record = await storage.loadSenderKey(senderName)
				if (record.isEmpty()) {
					// Check if this is a message from our own device (same user, different device)
					const { user: authorUser } = jidDecode(authorJid)!
					const meId = (auth.creds as any).me?.id
					const { user: meUser } = meId ? jidDecode(meId)! : { user: null }
					
					if (authorUser === meUser && meId) {
						console.debug(`Message from our own device ${authorJid} - attempting cross-device sender key lookup`)
						
						// Try to find sender keys from any of our own devices for this group
						const myDevicePrefix = `${group}::${meUser}::`
						const allSenderKeys = await auth.keys.get('sender-key', [])
						
						console.debug(`Looking for sender keys with prefix: ${myDevicePrefix}`)
						console.debug(`Available sender keys:`, Object.keys(allSenderKeys || {}))
						
						// Look for any sender key from our own devices in this group
						const ownDeviceKeys = Object.keys(allSenderKeys || {}).filter(key => key.startsWith(myDevicePrefix))
						
						if (ownDeviceKeys.length > 0) {
							console.debug(`Found ${ownDeviceKeys.length} sender keys from our own devices:`, ownDeviceKeys)
							// For now, just log this - we could potentially copy/derive keys here
							// TODO: Implement sender key copying/sharing between own devices
						}
					}
					
					console.debug(`Sender key record is empty for ${senderName.toString()} - triggering retry`)
					throw new Error(`No sender key found for ${senderName.toString()}`)
				}
				
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
			console.log(`[DEBUG] Encrypting group message for group: ${group}, sender: ${senderNameStr}`)

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { [senderNameStr]: senderKey } = await auth.keys.get('sender-key', [senderNameStr])
				console.log(`[DEBUG] Existing sender key found: ${!!senderKey}`)
				
				if (!senderKey) {
					console.log(`[DEBUG] Creating new sender key record for ${senderNameStr}`)
					await storage.storeSenderKey(senderName, new SenderKeyRecord())
				}

				const senderKeyDistributionMessage = await builder.create(senderName)
				console.log(`[DEBUG] Created sender key distribution message, size: ${senderKeyDistributionMessage.serialize().length} bytes`)
				
				const session = new GroupCipher(storage, senderName)
				const ciphertext = await session.encrypt(data)
				console.log(`[DEBUG] Encrypted message, ciphertext size: ${ciphertext.length} bytes`)

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
			const { [keyId]: key } = await keys.get('sender-key', [keyId])
			if (key) {
				return SenderKeyRecord.deserialize(key)
			}

			// Return empty record to satisfy interface - we'll check validity in decryption
			return new SenderKeyRecord()
		},
		storeSenderKey: async (senderKeyName: SenderKeyName, key: SenderKeyRecord) => {
			const keyId = senderKeyName.toString()
			const serialized = JSON.stringify(key.serialize())
			await keys.set({ 'sender-key': { [keyId]: Buffer.from(serialized, 'utf-8') } })
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
