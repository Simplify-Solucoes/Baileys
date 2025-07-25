import { crypto } from '@wppconnect-team/libsignal-protocol'

export class SenderMessageKey {
	private readonly _iteration: number
	private readonly _iv: Uint8Array
	private readonly _cipherKey: Uint8Array
	private readonly seed: Uint8Array

	constructor(iteration: number, seed: Uint8Array) {
		const derivative = crypto.HKDF(seed, new Uint8Array(32), 'WhisperGroup')
		const keys = new Uint8Array(32)
		keys.set(new Uint8Array(derivative[0]!.slice(16)))
		keys.set(new Uint8Array(derivative[1]!.slice(0, 16)), 16)

		this._iv = Buffer.from(derivative[0]!.slice(0, 16))
		this._cipherKey = Buffer.from(keys.buffer)
		this._iteration = iteration
		this.seed = seed
	}

	public getIteration(): number {
		return this._iteration
	}

	public getIv(): Uint8Array {
		return this._iv
	}

	public getCipherKey(): Uint8Array {
		return this._cipherKey
	}

	public getSeed(): Uint8Array {
		return this.seed
	}

	// Getters for WPPConnect compatibility
	public get iteration(): number {
		return this._iteration
	}

	public get iv(): Uint8Array {
		return this._iv
	}

	public get cipherKey(): Uint8Array {
		return this._cipherKey
	}
}
