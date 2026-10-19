import { jest } from '@jest/globals'
import { setImmediate as nextTurn } from 'timers/promises'
import { DEFAULT_CONNECTION_CONFIG, NOISE_WA_HEADER } from '../../Defaults'
import { WebSocketClient } from '../../Socket/Client/websocket'
import { makeSocket } from '../../Socket/socket'
import type { AuthenticationCreds, SignalKeyStore } from '../../Types'
import { initAuthCreds } from '../../Utils/auth-utils'
import logger from '../../Utils/logger'
import { decodeBinaryNode } from '../../WABinary'

const FRAME_LENGTH_BYTES = 3
const ORIGINAL_NAME = 'Original name'
const UPDATED_NAME = 'Updated name'
const TEST_USER_ID = '123456789@s.whatsapp.net'

describe('credential update presence', () => {
	let socket: ReturnType<typeof makeSocket>
	let send: jest.SpiedFunction<WebSocketClient['send']>

	beforeEach(() => {
		jest.spyOn(WebSocketClient.prototype, 'connect').mockImplementation(() => {})
		jest.spyOn(WebSocketClient.prototype, 'isOpen', 'get').mockReturnValue(true)
		send = jest.spyOn(WebSocketClient.prototype, 'send').mockImplementation((_frame, callback) => {
			callback?.()
			return true
		})
		const creds = initAuthCreds()
		creds.me = { id: TEST_USER_ID, name: ORIGINAL_NAME }
		const keys: SignalKeyStore = {
			async get() {
				return {}
			},
			async set() {}
		}
		socket = makeSocket({
			...DEFAULT_CONNECTION_CONFIG,
			markOnlineOnConnect: false,
			logger: logger.child({}, { level: 'silent' }),
			auth: { creds, keys }
		})
	})

	afterEach(async () => {
		await socket.end(undefined)
		jest.restoreAllMocks()
	})

	it.each<Partial<AuthenticationCreds>>([
		{ nextPreKeyId: 42 },
		{ me: { id: TEST_USER_ID } },
		{ me: { id: TEST_USER_ID, name: '' } },
		{ me: { id: TEST_USER_ID, name: ORIGINAL_NAME } }
	])('does not announce presence for a credential patch without a new nonempty name: %j', async update => {
		socket.ev.emit('creds.update', update)
		await nextTurn()

		expect(send).not.toHaveBeenCalled()
		expect(socket.authState.creds).toMatchObject(update)
	})

	it('announces a changed name and persists the credentials', async () => {
		socket.ev.emit('creds.update', { me: { id: TEST_USER_ID, name: UPDATED_NAME } })
		await nextTurn()

		expect(send).toHaveBeenCalledTimes(1)
		const frame = send.mock.calls[0]?.[0]
		if (typeof frame === 'string' || !frame) {
			throw new Error('Expected a binary presence frame')
		}

		const node = await decodeBinaryNode(Buffer.from(frame).subarray(NOISE_WA_HEADER.length + FRAME_LENGTH_BYTES))
		expect(node.tag).toBe('presence')
		expect(node.attrs).toEqual({ name: UPDATED_NAME })
		expect(socket.authState.creds.me?.name).toBe(UPDATED_NAME)
	})
})
