import { jest } from '@jest/globals'
import { AsyncLocalStorage } from 'async_hooks'
import { setImmediate as nextTurn } from 'timers/promises'
import makeWASocket from '../../Socket'
import { WebSocketClient } from '../../Socket/Client/websocket'
import type { SignalDataSet, SignalDataTypeMap, SignalKeyStore } from '../../Types'
import { initAuthCreds } from '../../Utils/auth-utils'
import type { ILogger } from '../../Utils/logger'
import { StaleSocketTaskError } from '../../Utils/socket-task-guard'

const SOCKET_CYCLES = 100
const LIFECYCLE_TEST_TIMEOUT_MS = 30_000

const makeTestLogger = (): ILogger =>
	({
		level: 'silent',
		child: () => makeTestLogger(),
		trace: () => {},
		debug: () => {},
		info: () => {},
		warn: () => {},
		error: () => {},
		fatal: () => {}
	}) as unknown as ILogger

describe('socket async context lifecycle', () => {
	it(
		'bounds storage across socket recreation while rejecting pending writes from closed generations',
		async () => {
			const connect = jest.spyOn(WebSocketClient.prototype, 'connect').mockImplementation(() => {})
			const run = jest.spyOn(AsyncLocalStorage.prototype, 'run')
			const persisted: SignalDataSet[] = []

			try {
				for (let cycle = 0; cycle < SOCKET_CYCLES; cycle++) {
					const keys: SignalKeyStore = {
						async get<T extends keyof SignalDataTypeMap>(): Promise<{ [id: string]: SignalDataTypeMap[T] }> {
							return {}
						},
						async set(data) {
							persisted.push(data)
						}
					}
					const socket = makeWASocket({ auth: { creds: initAuthCreds(), keys }, logger: makeTestLogger() })
					try {
						await nextTurn()
						await socket.socketTaskGuard.run(() => socket.authState.keys.transaction(async () => {}, 'warmup'))
						let resume: (() => void) | undefined
						const gate = new Promise<void>(resolve => {
							resume = resolve
						})
						const pending = socket.socketTaskGuard.run(async () => {
							await gate
							await socket.authState.keys.transaction(async () => {
								await socket.authState.keys.set({ session: { stale: new Uint8Array([1]) } })
							}, 'stale')
						})

						await socket.end(undefined)
						resume?.()
						await expect(pending).rejects.toBeInstanceOf(StaleSocketTaskError)
					} finally {
						await socket.end(undefined)
					}
				}

				expect(persisted).toEqual([])
				expect(new Set(run.mock.contexts).size).toBe(2)
				expect(connect).toHaveBeenCalledTimes(SOCKET_CYCLES)
			} finally {
				run.mockRestore()
				connect.mockRestore()
			}
		},
		LIFECYCLE_TEST_TIMEOUT_MS
	)
})
