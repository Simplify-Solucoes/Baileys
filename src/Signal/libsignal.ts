/* @ts-ignore */
import * as libsignal from 'libsignal'
import { LRUCache } from 'lru-cache'
import type { SignalAuthState, SignalKeyStoreWithTransaction } from '../Types'
import type { SignalRepository } from '../Types/Signal'
import { generateSignalPubKey } from '../Utils'
import { jidDecode } from '../WABinary'
import { LIDMappingStore } from '../Utils/lid-mapping'
import type { SenderKeyStore } from './Group/group_cipher'
import { SenderKeyName } from './Group/sender-key-name'
import { SenderKeyRecord } from './Group/sender-key-record'
import { GroupCipher, GroupSessionBuilder, SenderKeyDistributionMessage } from './Group'

export function makeLibSignalRepository(auth: SignalAuthState): SignalRepository {
	const lidMapping = new LIDMappingStore(auth.keys as SignalKeyStoreWithTransaction)
	const storage = signalStorage(auth, lidMapping)	
	// Simple operation-level deduplication (5 minutes)
	const recentMigrations = new LRUCache<string, boolean>({
		max: 500,
		ttl: 5 * 60 * 1000
	})
	

	const repository: SignalRepository = {
		decryptGroupMessage({ group, authorJid, msg }) {
			const senderName = jidToSignalSenderKeyName(group, authorJid)
			const cipher = new GroupCipher(storage, senderName)
			
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				return cipher.decrypt(msg)
			})
		},

		async processSenderKeyDistributionMessage({ item, authorJid }) {
			const builder = new GroupSessionBuilder(storage)
			if (!item.groupId) {
				throw new Error('Group ID is required')
			}

			const senderName = jidToSignalSenderKeyName(item.groupId, authorJid)
			const senderMsg = new SenderKeyDistributionMessage(
				null, null, null, null,
				item.axolotlSenderKeyDistributionMessage
			)

			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const senderNameStr = senderName.toString()
				const { [senderNameStr]: senderKey } = await auth.keys.get('sender-key', [senderNameStr])
				
				if (!senderKey) {
					await storage.storeSenderKey(senderName, new SenderKeyRecord())
				}

				await builder.process(senderName, senderMsg)
			})
		},

		async decryptMessage({ jid, type, ciphertext }) {
			const addr = jidToSignalProtocolAddress(jid)
			const session = new libsignal.SessionCipher(storage as any, addr)
			
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				switch (type) {
					case 'pkmsg':
						return session.decryptPreKeyWhisperMessage(ciphertext)
					case 'msg':
						return session.decryptWhisperMessage(ciphertext)
					default:
						throw new Error(`Unknown message type: ${type}`)
				}
			})
		},

		async encryptMessage({ jid, data }) {
			// LID SINGLE SOURCE OF TRUTH: Always prefer LID when available
			let encryptionJid = jid
			
			// Check for LID mapping and use it if session exists
			if (jid.includes('@s.whatsapp.net')) {
				try {
					const lidForPN = await lidMapping.getLIDForPN(jid)
					if (lidForPN && lidForPN.includes('@lid')) {
						const lidAddr = jidToSignalProtocolAddress(lidForPN)
						const { [lidAddr.toString()]: lidSession } = await auth.keys.get('session', [lidAddr.toString()])
						
						if (lidSession) {
							// LID session exists, use it
							encryptionJid = lidForPN
						} else {
							// Try to migrate if PN session exists
							const pnAddr = jidToSignalProtocolAddress(jid)
							const { [pnAddr.toString()]: pnSession } = await auth.keys.get('session', [pnAddr.toString()])
							
							if (pnSession) {
								// Migrate PN to LID
								await repository.migrateSession(jid, lidForPN)
								encryptionJid = lidForPN
							}
						}
					}
				} catch (error) {
					// Fallback to original JID on any error
				}
			}
			
			const addr = jidToSignalProtocolAddress(encryptionJid)
			const cipher = new libsignal.SessionCipher(storage as any, addr)
			
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { type: sigType, body } = await cipher.encrypt(data)
				const type = sigType === 3 ? 'pkmsg' : 'msg'
				return { type, ciphertext: Buffer.from(body as any, 'binary') }
			})
		},

		async encryptGroupMessage({ group, meId, data }) {
			const senderName = jidToSignalSenderKeyName(group, meId)
			const builder = new GroupSessionBuilder(storage)

			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const senderNameStr = senderName.toString()
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
			const cipher = new libsignal.SessionBuilder(storage as any, jidToSignalProtocolAddress(jid))
			const bundle: any = {
				registrationId: session.registrationId,
				identityKey: Buffer.from(session.identityKey),
				signedPreKey: {
					keyId: session.signedPreKey.keyId,
					keyPair: {
						pubKey: Buffer.from(session.signedPreKey.publicKey),
						privKey: Buffer.alloc(32)
					},
					signature: session.signedPreKey.signature
				}
			}

			if (session.preKey) {
				bundle.preKey = {
					keyId: session.preKey.keyId,
					keyPair: {
						pubKey: Buffer.from(session.preKey.publicKey),
						privKey: Buffer.alloc(32)
					}
				}
			}

			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				await cipher.initOutgoing(bundle)
			})
		},

		jidToSignalProtocolAddress(jid) {
			return jidToSignalProtocolAddress(jid).toString()
		},

		async storeLIDPNMapping(lid: string, pn: string) {
			await lidMapping.storeLIDPNMapping(lid, pn)
		},

		getLIDMappingStore() {
			return lidMapping
		},

		async validateSession(jid: string) {
			try {
				const addr = jidToSignalProtocolAddress(jid)
				const session = await storage.loadSession(addr.toString())
				
				if (!session) {
					return { exists: false, reason: "no session" }
				}
				
				if (!session.haveOpenSession()) {
					return { exists: false, reason: "no open session" }
				}
				
				return { exists: true }
			} catch (error) {
				return { exists: false, reason: "validation error" }
			}
		},

		shouldRecreateSession(_jid: string, retryCount: number) {
			// Simple threshold - let WhatsApp server dictate when recreation is needed
			return retryCount >= 2 
				? { shouldRecreate: true, reason: 'retry threshold met' }
				: { shouldRecreate: false, reason: 'retry count below threshold' }
		},

		async recreateSession(jid: string) {
			const addr = jidToSignalProtocolAddress(jid)
			
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				await auth.keys.set({ session: { [addr.toString()]: null } })
			})
		},

		async deleteSession(jid: string) {
			const addr = jidToSignalProtocolAddress(jid)
			
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				await auth.keys.set({ session: { [addr.toString()]: null } })
			})
		},

		async migrateSession(fromJid: string, toJid: string) {
			// Only migrate PN → LID
			if (!fromJid.includes('@s.whatsapp.net') || !toJid.includes('@lid')) {
				return
			}
			
			const fromDecoded = jidDecode(fromJid)
			const toDecoded = jidDecode(toJid)
			if (!fromDecoded || !toDecoded) return
			
			const deviceId = fromDecoded.device || 0
			const migrationKey = `${fromDecoded.user}.${deviceId}→${toDecoded.user}.${deviceId}`
			
			// Check if recently migrated (5 min window)
			if (recentMigrations.has(migrationKey)) {
				return
			}
			
			// Check if LID session already exists
			const lidAddr = jidToSignalProtocolAddress(toJid)
			const { [lidAddr.toString()]: lidExists } = await auth.keys.get('session', [lidAddr.toString()])
			if (lidExists) {
				recentMigrations.set(migrationKey, true)
				return
			}
			
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				// Store mapping
				await lidMapping.storeLIDPNMapping(toJid, fromJid)
				
				// Load and copy session
				const fromAddr = jidToSignalProtocolAddress(fromJid)
				const fromSession = await storage.loadSession(fromAddr.toString())
				
				if (fromSession && fromSession.haveOpenSession()) {
					// Deep copy session to prevent reference issues
					const sessionBytes = fromSession.serialize()
					const copiedSession = libsignal.SessionRecord.deserialize(sessionBytes)
					
					// Store at LID address
					await storage.storeSession(lidAddr.toString(), copiedSession)
					
					// Delete PN session - maintain single encryption layer
					await auth.keys.set({ session: { [fromAddr.toString()]: null } })
				}
				
				recentMigrations.set(migrationKey, true)
			})
		},

		async encryptMessageWithWire({ encryptionJid, wireJid, data }) {
			const result = await repository.encryptMessage({ jid: encryptionJid, data })
			return { ...result, wireJid }
		},

		destroy() {
			recentMigrations.clear()
		}
	}

	return repository
}

const jidToSignalProtocolAddress = (jid: string) => {
	const decoded = jidDecode(jid)!
	const { user, device, server } = decoded
	
	// LID addresses get _1 suffix for Signal protocol
	const signalUser = server === 'lid' ? `${user}_1` : user
	const finalDevice = device || 0
	
	return new libsignal.ProtocolAddress(signalUser, finalDevice)
}

const jidToSignalSenderKeyName = (group: string, user: string): SenderKeyName => {
	return new SenderKeyName(group, jidToSignalProtocolAddress(user))
}

function signalStorage({ creds, keys }: SignalAuthState, lidMapping: LIDMappingStore): SenderKeyStore & Record<string, any> {
	return {
		loadSession: async (id: string) => {
			try {
				// LID SINGLE SOURCE OF TRUTH: Auto-redirect PN to LID if mapping exists
				let actualId = id
				if (id.includes('.') && !id.includes('_1')) {
					// This is a PN signal address format (e.g., "1234567890.0")
					// Convert back to JID to check for LID mapping
					const parts = id.split('.')
					const device = parts[1] || '0'
					const pnJid = device === '0' 
						? `${parts[0]}@s.whatsapp.net`
						: `${parts[0]}:${device}@s.whatsapp.net`
					
					const lidForPN = await lidMapping.getLIDForPN(pnJid)
					if (lidForPN && lidForPN.includes('@lid')) {
						const lidAddr = jidToSignalProtocolAddress(lidForPN)
						const lidId = lidAddr.toString()
						
						// Check if LID session exists
						const { [lidId]: lidSession } = await keys.get('session', [lidId])
						if (lidSession) {
							actualId = lidId
						}
					}
				}
				
				const { [actualId]: sess } = await keys.get('session', [actualId])
				if (sess) {
					return libsignal.SessionRecord.deserialize(sess)
				}
			} catch (e) {
				return null
			}
			return null
		},
		
		storeSession: async (id: string, session: any) => {
			await keys.set({ session: { [id]: session.serialize() } })
		},
		
		isTrustedIdentity: async () => true,
		
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
			const serialized = key.serialize()
			const buffer = Buffer.from(JSON.stringify(serialized), 'utf-8')
			await keys.set({ 'sender-key': { [keyId]: buffer } })
		},
		
		getOurRegistrationId: async () => creds.registrationId,
		
		getOurIdentity: async () => {
			const { signedIdentityKey } = creds
			return {
				privKey: Buffer.from(signedIdentityKey.private),
				pubKey: Buffer.from(generateSignalPubKey(signedIdentityKey.public))
			}
		}
	}
}