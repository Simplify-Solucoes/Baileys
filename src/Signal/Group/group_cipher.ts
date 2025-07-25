import { crypto } from '@wppconnect-team/libsignal-protocol'
import { SenderKeyMessage } from './sender-key-message'
import { SenderKeyName } from './sender-key-name'
import { SenderKeyRecord } from './sender-key-record'
import { SenderKeyState } from './sender-key-state'

export interface SenderKeyStore {
	loadSenderKey(senderKeyName: SenderKeyName): Promise<SenderKeyRecord>
	storeSenderKey(senderKeyName: SenderKeyName, record: SenderKeyRecord): Promise<void>
}

/**
 * Handles group message encryption and decryption using the Sender Key protocol (Signal/libsignal).
 *
 * Reference: https://signal.org/docs/specifications/group/#sender-keys
 */
export class GroupCipher {
	private senderKeyStore: SenderKeyStore
	private senderKeyId: SenderKeyName

	/**
	 * @param senderKeyStore The storage interface for sender keys
	 * @param senderKeyId The (groupId, senderId, deviceId) tuple
	 */
	constructor(senderKeyStore: SenderKeyStore, senderKeyId: SenderKeyName) {
		this.senderKeyStore = senderKeyStore
		this.senderKeyId = senderKeyId
	}

	/**
	 * Encrypts a message for the group, returning a serialized SenderKeyMessage (with signature appended).
	 * @param paddedPlaintext The plaintext message bytes, optionally padded
	 * @returns Serialized SenderKeyMessage (protobuf + signature)
	 */
	async encrypt(paddedPlaintext: Uint8Array): Promise<Uint8Array> {
		const record = await this.senderKeyStore.loadSenderKey(this.senderKeyId)
		if (!record) {
			throw new Error('No SenderKeyRecord found for encryption')
		}

		const senderKeyState = record.getSenderKeyState()
		if (!senderKeyState) {
			throw new Error('No session to encrypt message')
		}

		const iteration = senderKeyState.getSenderChainKey().getIteration()
		const senderKey = this.getSenderKey(senderKeyState, iteration === 0 ? 0 : iteration + 1)

		const ciphertext = crypto.encrypt(senderKey.getCipherKey(), paddedPlaintext, senderKey.getIv())

		const senderKeyMessage = new SenderKeyMessage(
			senderKeyState.getKeyId(),
			senderKey.getIteration(),
			ciphertext,
			senderKeyState.getSigningKeyPrivate()
		)

		await this.senderKeyStore.storeSenderKey(this.senderKeyId, record)
		return senderKeyMessage.serialize()
	}

	/**
	 * Decrypts a group message from a serialized SenderKeyMessage (protobuf + signature).
	 * @param senderKeyMessageBytes The received serialized SenderKeyMessage (protobuf + signature)
	 * @returns Plaintext
	 */
	async decrypt(senderKeyMessageBytes: Uint8Array): Promise<Uint8Array> {
		const record = await this.senderKeyStore.loadSenderKey(this.senderKeyId)
		if (!record) {
			throw new Error('No SenderKeyRecord found for decryption')
		}

		const senderKeyMessage = new SenderKeyMessage(null, null, null, null, senderKeyMessageBytes)
		let senderKeyState = record.getSenderKeyState(senderKeyMessage.getKeyId())

		// Fallback: try to get the latest sender key state if specific keyId not found
		if (!senderKeyState) {
			senderKeyState = record.getSenderKeyState()
			if (!senderKeyState) {
				throw new Error('No session found to decrypt message')
			}
		}

		await senderKeyMessage.verifySignature(senderKeyState.getSigningKeyPublic())
		const senderKey = this.getSenderKey(senderKeyState, senderKeyMessage.getIteration())

		const plaintext = crypto.decrypt(senderKey.getCipherKey(), senderKeyMessage.getCipherText(), senderKey.getIv())

		await this.senderKeyStore.storeSenderKey(this.senderKeyId, record)
		return plaintext
	}

	private getSenderKey(senderKeyState: SenderKeyState, iteration: number) {
		let senderChainKey = senderKeyState.getSenderChainKey()
		if (senderChainKey.getIteration() > iteration) {
			if (senderKeyState.hasSenderMessageKey(iteration)) {
				const messageKey = senderKeyState.removeSenderMessageKey(iteration)
				if (!messageKey) {
					throw new Error('No sender message key found for iteration')
				}

				return messageKey
			}

			throw new Error(`Received message with old counter: ${senderChainKey.getIteration()}, ${iteration}`)
		}

		if (iteration - senderChainKey.getIteration() > 2000) {
			throw new Error('Over 2000 messages into the future!')
		}

		while (senderChainKey.getIteration() < iteration) {
			senderKeyState.addSenderMessageKey(senderChainKey.getSenderMessageKey())
			senderChainKey = senderChainKey.getNext()
		}

		senderKeyState.setSenderChainKey(senderChainKey.getNext())
		return senderChainKey.getSenderMessageKey()
	}

}
