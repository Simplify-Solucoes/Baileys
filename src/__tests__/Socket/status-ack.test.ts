import { jest } from '@jest/globals'
import { setImmediate as nextTurn } from 'timers/promises'
import { DEFAULT_CONNECTION_CONFIG, NOISE_WA_HEADER } from '../../Defaults'
import { WebSocketClient } from '../../Socket/Client/websocket'
import { makeMessagesRecvSocket } from '../../Socket/messages-recv'
import { initAuthCreds } from '../../Utils/auth-utils'
import logger from '../../Utils/logger'
import { type BinaryNode, decodeBinaryNode } from '../../WABinary'

const FRAME_LENGTH_BYTES = 3

afterEach(() => {
	jest.restoreAllMocks()
})

it.each([
	['online', undefined],
	['offline', '1'],
	['offline with a zero marker', '0'],
	['redelivered', '6'],
	['ignored sender', undefined]
] as const)('acknowledges an incoming %s status stanza', async (delivery, offline) => {
	jest.spyOn(WebSocketClient.prototype, 'connect').mockImplementation(() => {})
	jest.spyOn(WebSocketClient.prototype, 'isOpen', 'get').mockReturnValue(true)
	const send = jest.spyOn(WebSocketClient.prototype, 'send').mockImplementation((_frame, callback) => {
		callback?.()
		return true
	})
	const status: BinaryNode = {
		tag: 'status',
		attrs: { id: 'status-001', from: 'status@broadcast', participant: '1234@lid', type: 'media' }
	}
	if (offline !== undefined) {
		status.attrs.offline = offline
	}

	const creds = initAuthCreds()
	creds.me = { id: '5678@s.whatsapp.net', name: 'Test' }
	const socket = makeMessagesRecvSocket({
		...DEFAULT_CONNECTION_CONFIG,
		logger: logger.child({}, { level: 'silent' }),
		auth: { creds, keys: { get: async () => ({}), set: async () => {} } },
		shouldIgnoreJid: jid => delivery === 'ignored sender' && jid === status.attrs.from
	})
	try {
		await nextTurn()
		expect(socket.ws.emit('CB:status', status)).toBe(true)
		await nextTurn()

		expect(send).toHaveBeenCalledTimes(1)
		const frame = send.mock.calls[0]?.[0]
		if (!frame || typeof frame === 'string') {
			throw new Error('Expected a binary ACK')
		}

		const ack = await decodeBinaryNode(Buffer.from(frame).subarray(NOISE_WA_HEADER.length + FRAME_LENGTH_BYTES))
		expect(ack.tag).toBe('ack')
		expect(ack.attrs).toEqual({
			id: 'status-001',
			to: 'status@broadcast',
			participant: '1234@lid',
			class: 'status',
			type: 'media'
		})
	} finally {
		await socket.end(undefined)
	}
})
