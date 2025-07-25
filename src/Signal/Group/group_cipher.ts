/* @ts-ignore */
import { decrypt, encrypt } from 'libsignal/src/crypto'
import { SenderKeyMessage } from './sender-key-message'
import { SenderKeyName } from './sender-key-name'
import { SenderKeyRecord } from './sender-key-record'
import { SenderKeyState } from './sender-key-state'

export interface SenderKeyStore {
	loadSenderKey(senderKeyName: SenderKeyName): Promise<SenderKeyRecord>

	storeSenderKey(senderKeyName: SenderKeyName, record: SenderKeyRecord): Promise<void>
}

export class GroupCipher {
	private readonly senderKeyStore: SenderKeyStore
	private readonly senderKeyName: SenderKeyName

	constructor(senderKeyStore: SenderKeyStore, senderKeyName: SenderKeyName) {
		this.senderKeyStore = senderKeyStore
		this.senderKeyName = senderKeyName
	}

	public async encrypt(paddedPlaintext: Uint8Array | string): Promise<Uint8Array> {
		const record = await this.senderKeyStore.loadSenderKey(this.senderKeyName)
		if (!record) {
			throw new Error('No SenderKeyRecord found for encryption')
		}

		const senderKeyState = record.getSenderKeyState()
		if (!senderKeyState) {
			throw new Error('No session to encrypt message')
		}

		const iteration = senderKeyState.getSenderChainKey().getIteration()
		const senderKey = this.getSenderKey(senderKeyState, iteration === 0 ? 0 : iteration + 1)

		const ciphertext = await this.getCipherText(senderKey.getIv(), senderKey.getCipherKey(), paddedPlaintext)

		const senderKeyMessage = new SenderKeyMessage(
			senderKeyState.getKeyId(),
			senderKey.getIteration(),
			ciphertext,
			senderKeyState.getSigningKeyPrivate()
		)

		await this.senderKeyStore.storeSenderKey(this.senderKeyName, record)
		return senderKeyMessage.serialize()
	}

	public async decrypt(senderKeyMessageBytes: Uint8Array): Promise<Uint8Array> {
		const record = await this.senderKeyStore.loadSenderKey(this.senderKeyName)
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

		senderKeyMessage.verifySignature(senderKeyState.getSigningKeyPublic())
		const senderKey = this.getSenderKey(senderKeyState, senderKeyMessage.getIteration())

		const plaintext = await this.getPlainText(
			senderKey.getIv(),
			senderKey.getCipherKey(),
			senderKeyMessage.getCipherText()
		)

		await this.senderKeyStore.storeSenderKey(this.senderKeyName, record)
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

	private async getPlainText(iv: Uint8Array, key: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
		try {
			return decrypt(key, ciphertext, iv)
		} catch (e) {
			throw new Error('InvalidMessageException')
		}
	}

	private async getCipherText(
		iv: Uint8Array | string,
		key: Uint8Array | string,
		plaintext: Uint8Array | string
	): Promise<Buffer> {
		try {
			const ivBuffer = typeof iv === 'string' ? Buffer.from(iv, 'base64') : iv
			const keyBuffer = typeof key === 'string' ? Buffer.from(key, 'base64') : key
			const plaintextBuffer = typeof plaintext === 'string' ? Buffer.from(plaintext) : plaintext
			return encrypt(keyBuffer, plaintextBuffer, ivBuffer)
		} catch (e) {
			throw new Error('InvalidMessageException')
		}
	}
}
