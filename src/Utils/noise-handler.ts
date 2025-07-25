import { Boom } from '@hapi/boom'
import { proto } from '../../WAProto/index.js'
import { NOISE_MODE, WA_CERT_DETAILS } from '../Defaults'
import type { KeyPair } from '../Types'
import type { BinaryNode } from '../WABinary'
import { decodeBinaryNode } from '../WABinary'
import { aesDecryptGCM, aesEncryptGCM, Curve, generateSignalPubKey, hkdf, sha256 } from './crypto'
import type { ILogger } from './logger'

const generateIV = (counter: number) => {
	const iv = new ArrayBuffer(12)
	new DataView(iv).setUint32(8, counter)

	return new Uint8Array(iv)
}

export const makeNoiseHandler = ({
	keyPair: { private: privateKey, public: publicKey },
	NOISE_HEADER,
	logger,
	routingInfo
}: {
	keyPair: KeyPair
	NOISE_HEADER: Uint8Array
	logger: ILogger
	routingInfo?: Buffer | undefined
}) => {
	logger = logger.child({ class: 'ns' })

	const authenticate = (data: Uint8Array) => {
		if (!isFinished) {
			logger.trace({ 
				dataLength: data.length, 
				hashLength: hash.length,
				isFinished 
			}, 'noise: authenticating data')
			hash = sha256(Buffer.concat([hash, data]))
			logger.trace({ newHashLength: hash.length }, 'noise: hash updated')
		}
	}

	const encrypt = (plaintext: Uint8Array) => {
		logger.trace({ 
			plaintextLength: plaintext.length, 
			encKeyLength: encKey.length,
			writeCounter,
			hashLength: hash.length 
		}, 'noise: encrypting data')
		
		const iv = generateIV(writeCounter)
		logger.trace({ ivLength: iv.length, writeCounter }, 'noise: generated IV')
		
		const result = aesEncryptGCM(plaintext, encKey, iv, hash)
		logger.trace({ resultLength: result.length }, 'noise: encryption complete')

		writeCounter += 1

		authenticate(result)
		return result
	}

	const decrypt = (ciphertext: Uint8Array) => {
		// before the handshake is finished, we use the same counter
		// after handshake, the counters are different
		const iv = generateIV(isFinished ? readCounter : writeCounter)
		const result = aesDecryptGCM(ciphertext, decKey, iv, hash)

		if (isFinished) {
			readCounter += 1
		} else {
			writeCounter += 1
		}

		authenticate(ciphertext)
		return result
	}

	const localHKDF = async (data: Uint8Array) => {
		const key = await hkdf(Buffer.from(data), 64, { salt, info: '' })
		return [key.slice(0, 32), key.slice(32)]
	}

	const mixIntoKey = async (data: Uint8Array) => {
		const [write, read] = await localHKDF(data)
		salt = write!
		encKey = read!
		decKey = read!
		readCounter = 0
		writeCounter = 0
	}

	const finishInit = async () => {
		const [write, read] = await localHKDF(new Uint8Array(0))
		encKey = write!
		decKey = read!
		hash = Buffer.from([])
		readCounter = 0
		writeCounter = 0
		isFinished = true
	}

	const data = Buffer.from(NOISE_MODE)
	let hash = data.byteLength === 32 ? data : sha256(data)
	let salt = hash
	let encKey = hash
	let decKey = hash
	let readCounter = 0
	let writeCounter = 0
	let isFinished = false
	let sentIntro = false

	let inBytes = Buffer.alloc(0)

	authenticate(NOISE_HEADER)
	authenticate(publicKey)

	return {
		encrypt,
		decrypt,
		authenticate,
		mixIntoKey,
		finishInit,
		processHandshake: async ({ serverHello }: proto.HandshakeMessage, noiseKey: KeyPair) => {
			logger.info('noise: starting handshake process')
			
			// Step 1: Authenticate server ephemeral key
			logger.trace({ 
				ephemeralLength: serverHello!.ephemeral!.length 
			}, 'noise: step 1 - authenticating server ephemeral key')
			authenticate(serverHello!.ephemeral!)

			// Step 2: Mix in shared secret from client private + server ephemeral
			logger.trace('noise: step 2 - calculating shared secret (client priv + server ephemeral)')
			const sharedSecret1 = Curve.sharedKey(privateKey, serverHello!.ephemeral!)
			logger.trace({ 
				sharedSecretLength: sharedSecret1.length,
				clientPrivateKeyLength: privateKey.length,
				serverEphemeralLength: serverHello!.ephemeral!.length
			}, 'noise: shared secret 1 calculated')
			await mixIntoKey(sharedSecret1)

			// Step 3: Decrypt server static key
			logger.trace({ 
				staticLength: serverHello!.static!.length 
			}, 'noise: step 3 - decrypting server static key')
			const decStaticContent = decrypt(serverHello!.static!)
			logger.trace({ 
				decStaticLength: decStaticContent.length 
			}, 'noise: server static key decrypted')

			// Step 4: Mix in shared secret from client private + server static
			logger.trace('noise: step 4 - calculating shared secret (client priv + server static)')
			const sharedSecret2 = Curve.sharedKey(privateKey, decStaticContent)
			logger.trace({ 
				sharedSecretLength: sharedSecret2.length 
			}, 'noise: shared secret 2 calculated')
			await mixIntoKey(sharedSecret2)

			// Step 5: Decrypt server certificate
			logger.trace({ 
				payloadLength: serverHello!.payload!.length 
			}, 'noise: step 5 - decrypting server certificate')
			const certDecoded = decrypt(serverHello!.payload!)
			logger.trace({ 
				certDecodedLength: certDecoded.length 
			}, 'noise: server certificate decrypted')

			// Step 6: Verify certificate
			logger.trace('noise: step 6 - verifying certificate')
			const { intermediate: certIntermediate } = proto.CertChain.decode(certDecoded)
			const { issuerSerial } = proto.CertChain.NoiseCertificate.Details.decode(certIntermediate!.details!)
			
			logger.trace({ 
				issuerSerial: issuerSerial?.toString('hex'),
				expectedSerial: WA_CERT_DETAILS.SERIAL.toString('hex')
			}, 'noise: checking certificate serial')

			if (issuerSerial !== WA_CERT_DETAILS.SERIAL) {
				logger.error({ 
					issuerSerial: issuerSerial?.toString('hex'),
					expectedSerial: WA_CERT_DETAILS.SERIAL.toString('hex')
				}, 'noise: certificate serial mismatch')
				throw new Boom('certification match failed', { statusCode: 400 })
			}

			// Step 7: Encrypt client noise key
			logger.trace({ 
				noiseKeyLength: noiseKey.public.length 
			}, 'noise: step 7 - encrypting client noise key')
			const noiseKeyWithVersion = generateSignalPubKey(noiseKey.public)
			logger.trace({ 
				noiseKeyWithVersionLength: noiseKeyWithVersion.length 
			}, 'noise: noise key with version byte prepared')
			
			const keyEnc = encrypt(noiseKeyWithVersion)
			logger.trace({ 
				keyEncLength: keyEnc.length 
			}, 'noise: client noise key encrypted')

			// Step 8: Final shared secret mixing
			logger.trace('noise: step 8 - final shared secret mixing (noise priv + server ephemeral)')
			const sharedSecret3 = Curve.sharedKey(noiseKey.private, serverHello!.ephemeral!)
			logger.trace({ 
				sharedSecretLength: sharedSecret3.length 
			}, 'noise: shared secret 3 calculated')
			await mixIntoKey(sharedSecret3)

			logger.info({ 
				keyEncLength: keyEnc.length 
			}, 'noise: handshake process completed')
			return keyEnc
		},
		encodeFrame: (data: Buffer | Uint8Array) => {
			if (isFinished) {
				data = encrypt(data)
			}

			let header: Buffer

			if (routingInfo) {
				header = Buffer.alloc(7)
				header.write('ED', 0, 'utf8')
				header.writeUint8(0, 2)
				header.writeUint8(1, 3)
				header.writeUint8(routingInfo.byteLength >> 16, 4)
				header.writeUint16BE(routingInfo.byteLength & 65535, 5)
				header = Buffer.concat([header, routingInfo, NOISE_HEADER])
			} else {
				header = Buffer.from(NOISE_HEADER)
			}

			const introSize = sentIntro ? 0 : header.length
			const frame = Buffer.alloc(introSize + 3 + data.byteLength)

			if (!sentIntro) {
				frame.set(header)
				sentIntro = true
			}

			frame.writeUInt8(data.byteLength >> 16, introSize)
			frame.writeUInt16BE(65535 & data.byteLength, introSize + 1)
			frame.set(data, introSize + 3)

			return frame
		},
		decodeFrame: async (newData: Buffer | Uint8Array, onFrame: (buff: Uint8Array | BinaryNode) => void) => {
			// the binary protocol uses its own framing mechanism
			// on top of the WS frames
			// so we get this data and separate out the frames
			const getBytesSize = () => {
				if (inBytes.length >= 3) {
					return (inBytes.readUInt8() << 16) | inBytes.readUInt16BE(1)
				}
			}

			inBytes = Buffer.concat([inBytes, newData])

			logger.trace(`recv ${newData.length} bytes, total recv ${inBytes.length} bytes`)

			let size = getBytesSize()
			while (size && inBytes.length >= size + 3) {
				let frame: Uint8Array | BinaryNode = inBytes.slice(3, size + 3)
				inBytes = inBytes.slice(size + 3)

				if (isFinished) {
					const result = decrypt(frame)
					frame = await decodeBinaryNode(result)
				}

				logger.trace({ msg: (frame as BinaryNode)?.attrs?.id }, 'recv frame')

				onFrame(frame)
				size = getBytesSize()
			}
		}
	}
}
