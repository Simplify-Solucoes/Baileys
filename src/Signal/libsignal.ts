import { SessionCipher, SessionBuilder, SignalProtocolAddress } from '@wppconnect-team/libsignal-protocol'
import { SessionRecord } from '@wppconnect-team/libsignal-protocol/lib/session-record'
import type { StorageType } from '@wppconnect-team/libsignal-protocol'
import type { SignalAuthState, SignalKeyStoreWithTransaction } from '../Types'
import type { SignalRepository } from '../Types/Signal'
import { generateSignalPubKey } from '../Utils'
import { jidDecode } from '../WABinary'
import type { SenderKeyStore } from './Group/group_cipher'
import { SenderKeyName } from './Group/sender-key-name'
import { SenderKeyRecord } from './Group/sender-key-record'
import { GroupCipher, GroupSessionBuilder, SenderKeyDistributionMessage } from './Group'

export function makeLibSignalRepository(auth: SignalAuthState): SignalRepository {
	const storage = signalStorage(auth)
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
			const session = new SessionCipher(storage, addr)

			// Use transaction to ensure atomicityAdd commentMore actions
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				let result: Uint8Array
				switch (type) {
					case 'pkmsg':
						result = await session.decryptPreKeyWhisperMessage(ciphertext)
						break
					case 'msg':
						result = await session.decryptWhisperMessage(ciphertext)
						break
				}

				return Buffer.from(result!)
			})
		},
		async encryptMessage({ jid, data }) {
			const addr = jidToSignalProtocolAddress(jid)
			const cipher = new SessionCipher(storage, addr)

			// Use transaction to ensure atomicityAdd commentMore actions
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				const { type: sigType, body } = await cipher.encrypt(data)
				const type = sigType === 3 ? 'pkmsg' : 'msg'
				return { type, ciphertext: Buffer.from(body || '') }
			})
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
			const builder = new SessionBuilder(storage, jidToSignalProtocolAddress(jid))

			// Use transaction to ensure atomicity
			return (auth.keys as SignalKeyStoreWithTransaction).transaction(async () => {
				await builder.processPreKey(session)
			})
		},
		jidToSignalProtocolAddress(jid) {
			return jidToSignalProtocolAddress(jid).toString()
		}
	}
}

const jidToSignalProtocolAddress = (jid: string) => {
	const { user, device } = jidDecode(jid)!
	return new SignalProtocolAddress(user, device || 0)
}

const jidToSignalSenderKeyName = (group: string, user: string): SenderKeyName => {
	const addr = jidToSignalProtocolAddress(user)
	return new SenderKeyName(group, { id: addr.name, deviceId: addr.deviceId } as any)
}

function signalStorage({ creds, keys }: SignalAuthState): StorageType & SenderKeyStore & Record<string, any> {
	return {
		// StorageType interface methods
		getIdentityKeyPair: async () => {
			const { signedIdentityKey } = creds
			return {
				privKey: signedIdentityKey.private,
				pubKey: generateSignalPubKey(signedIdentityKey.public)
			}
		},
		getLocalRegistrationId: async () => creds.registrationId,
		isTrustedIdentity: async () => true,
		saveIdentity: async () => true,
		storePreKey: async (keyId: number | string, keyPair: any) => {
			await keys.set({ 'pre-key': { [keyId.toString()]: keyPair } })
		},
		removePreKey: async (keyId: number | string) => {
			await keys.set({ 'pre-key': { [keyId.toString()]: null } })
		},
		storeSignedPreKey: async () => {}, // Not used in current implementation
		removeSignedPreKey: async () => {}, // Not used in current implementation
		
		// Original session methods
		loadSession: async (id: string) => {
			const { [id]: sess } = await keys.get('session', [id])
			if (sess) {
				return SessionRecord.deserialize(Buffer.from(sess).toString('utf-8')).serialize()
			}
		},
		storeSession: async (id: string, record: string) => {
			await keys.set({ session: { [id]: Buffer.from(record, 'utf-8') } })
		},
		loadPreKey: async (id: number | string) => {
			const keyId = id.toString()
			const { [keyId]: key } = await keys.get('pre-key', [keyId])
			if (key) {
				return {
					privKey: Buffer.from(key.private),
					pubKey: Buffer.from(key.public)
				}
			}
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
			const serialized = JSON.stringify(key.serialize())
			await keys.set({ 'sender-key': { [keyId]: Buffer.from(serialized, 'utf-8') } })
		},
		getOurRegistrationId: () => creds.registrationId,
		getOurIdentity: () => {
			const { signedIdentityKey } = creds
			return {
				privKey: Buffer.from(signedIdentityKey.private),
				pubKey: generateSignalPubKey(signedIdentityKey.public)
			}
		}
	}
}
