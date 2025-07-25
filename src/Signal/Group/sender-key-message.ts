import { curve } from '@wppconnect-team/libsignal-protocol'
import { proto } from '../../../WAProto/index.js'
import { CiphertextMessage } from './ciphertext-message'

interface SenderKeyMessageStructure {
	id: number
	iteration: number
	ciphertext: string | Buffer
}

export class SenderKeyMessage extends CiphertextMessage {
	static async create(
		keyId: number,
		iteration: number,
		ciphertext: Uint8Array,
		signingKeyPrivate: Uint8Array
	): Promise<SenderKeyMessage> {
		return new SenderKeyMessage(keyId, iteration, ciphertext, signingKeyPrivate)
	}

	static fromSerialized(serialized: Uint8Array): SenderKeyMessage {
		return new SenderKeyMessage(null, null, null, null, serialized)
	}
	private readonly SIGNATURE_LENGTH = 64
	private readonly messageVersion: number
	private readonly _keyId: number
	private readonly iteration: number
	private readonly _ciphertext: Uint8Array
	private readonly signature: Uint8Array
	private readonly serialized: Uint8Array

	constructor(
		keyId?: number | null,
		iteration?: number | null,
		ciphertext?: Uint8Array | null,
		signatureKey?: Uint8Array | null,
		serialized?: Uint8Array | null
	) {
		super()

		if (serialized) {
			const version = serialized[0]!
			const message = serialized.slice(1, serialized.length - this.SIGNATURE_LENGTH)
			const signature = serialized.slice(-1 * this.SIGNATURE_LENGTH)
			const senderKeyMessage = proto.SenderKeyMessage.decode(message).toJSON() as SenderKeyMessageStructure

			this.serialized = serialized
			this.messageVersion = (version & 0xff) >> 4
			this._keyId = senderKeyMessage.id
			this.iteration = senderKeyMessage.iteration
			this._ciphertext =
				typeof senderKeyMessage.ciphertext === 'string'
					? Buffer.from(senderKeyMessage.ciphertext, 'base64')
					: senderKeyMessage.ciphertext
			this.signature = signature
		} else {
			const version = (((this.CURRENT_VERSION << 4) | this.CURRENT_VERSION) & 0xff) % 256
			const ciphertextBuffer = Buffer.from(ciphertext!)
			const message = proto.SenderKeyMessage.encode(
				proto.SenderKeyMessage.create({
					id: keyId!,
					iteration: iteration!,
					ciphertext: ciphertextBuffer
				})
			).finish()

			const signature = this.getSignature(signatureKey!, Buffer.concat([Buffer.from([version]), message]))

			this.serialized = Buffer.concat([Buffer.from([version]), message, Buffer.from(signature)])
			this.messageVersion = this.CURRENT_VERSION
			this._keyId = keyId!
			this.iteration = iteration!
			this._ciphertext = ciphertextBuffer
			this.signature = signature
		}
	}

	public getKeyId(): number {
		return this._keyId
	}

	public get keyId(): number {
		return this._keyId
	}

	public getIteration(): number {
		return this.iteration
	}

	public getCipherText(): Uint8Array {
		return this._ciphertext
	}

	public async verifySignature(signatureKey: Uint8Array): Promise<boolean> {
		const part1 = this.serialized.slice(0, this.serialized.length - this.SIGNATURE_LENGTH)
		const part2 = this.serialized.slice(-1 * this.SIGNATURE_LENGTH)
		return curve.Ed25519Verify(signatureKey, part1, part2)
	}

	public get ciphertext(): Uint8Array {
		return this._ciphertext
	}

	private getSignature(signatureKey: Uint8Array, serialized: Uint8Array): Uint8Array {
		return Buffer.from(curve.Ed25519Sign(signatureKey, serialized))
	}

	public serialize(): Uint8Array {
		return this.serialized
	}

	public getType(): number {
		return 4
	}
}
