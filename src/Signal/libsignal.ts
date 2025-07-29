/* @ts-ignore */
import * as libsignal from 'libsignal'
import type { StorageType } from 'libsignal/src/types'
import type { SignalAuthState, SignalKeyStoreWithTransaction } from '../Types'
import type { SignalRepository } from '../Types/Signal'
import { generateSignalPubKey } from '../Utils'
import { jidDecode } from '../WABinary'
import type { SenderKeyStore } from './Group/group_cipher'
import { SenderKeyName } from './Group/sender-key-name'
import { SenderKeyRecord } from './Group/sender-key-record'
import { GroupCipher, GroupSessionBuilder, SenderKeyDistributionMessage } from './Group'

export function makeLibSignalRepository(auth: SignalAuthState): SignalRepository {
	const storage: SenderKeyStore = signalStorage(auth)
	return {
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

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				await cipher.initOutgoing({
					registrationId: session.registrationId,
					identityKey: Buffer.from(session.identityKey),
					signedPreKey: session.signedPreKey,
					preKey: session.preKey
				} as any)
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

function signalStorage({ creds, keys }: SignalAuthState): SenderKeyStore & StorageType & Record<string, any> {
	return {
		loadSession: async (id: string) => {
			const { [id]: sess } = await keys.get('session', [id])
			if (sess) {
				return libsignal.SessionRecord.deserialize(sess)
			}
			return null
		},
		storeSession: async (id: string, session: any) => {
			const serialized = session.serialize ? session.serialize() : session
			await keys.set({ session: { [id]: serialized } })
		},
		isTrustedIdentity: async (address: string, identityKey: Buffer) => {
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
			throw new Error(`PreKey not found for keyId: ${keyId}`)
		},
		removePreKey: async (id: number) => {
			await keys.set({ 'pre-key': { [id]: null } })
		},
		loadSignedPreKey: async (keyId: number) => {
			const key = creds.signedPreKey
			return {
				privKey: Buffer.from(key.keyPair.private),
				pubKey: Buffer.from(key.keyPair.public)
			}
		},
		storeSignedPreKey: async (keyId: number, keyPair: any) => {
			// Implementation for storing signed pre-key
			// This is usually handled by the credential store
		},
		removeSignedPreKey: async (keyId: number) => {
			// Implementation for removing signed pre-key
			// This is usually handled by the credential store
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
		}
	}
}
