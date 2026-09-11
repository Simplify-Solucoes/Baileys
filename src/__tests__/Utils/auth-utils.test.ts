import { Boom } from '@hapi/boom'
import type { AuthenticationCreds, Contact, SignalDataSet, SignalDataTypeMap, SignalKeyStore } from '../../Types'
import { addTransactionCapability, assertMeId, initAuthCreds } from '../../Utils/auth-utils'
import type { ILogger } from '../../Utils/logger'
import { makeSocketTaskGuard, StaleSocketTaskError } from '../../Utils/socket-task-guard'

const credsWithMe = (me?: Partial<Contact>): AuthenticationCreds => ({
	...initAuthCreds(),
	me: me as Contact | undefined
})

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

const makeSignalKeyStore = (persist: (data: SignalDataSet) => Promise<void>): SignalKeyStore => ({
	async get<T extends keyof SignalDataTypeMap>(): Promise<{ [id: string]: SignalDataTypeMap[T] }> {
		return {}
	},
	set: persist
})

describe('assertMeId', () => {
	it('returns me.id when authenticated', () => {
		const creds = credsWithMe({ id: '5511999999999@s.whatsapp.net' })
		expect(assertMeId(creds)).toBe('5511999999999@s.whatsapp.net')
	})

	it('throws Boom 401 when creds.me is undefined', () => {
		const creds = credsWithMe(undefined)
		try {
			assertMeId(creds)
			throw new Error('expected throw')
		} catch (err) {
			expect(err).toBeInstanceOf(Boom)
			expect((err as Boom).output.statusCode).toBe(401)
			expect((err as Error).message).toMatch(/not authenticated/)
		}
	})

	it('throws Boom 401 when me has no id', () => {
		const creds = credsWithMe({})
		expect(() => assertMeId(creds)).toThrow(/not authenticated/)
	})

	it('throws Boom 401 when me.id is empty string', () => {
		const creds = credsWithMe({ id: '' })
		expect(() => assertMeId(creds)).toThrow(/not authenticated/)
	})
})

describe('addTransactionCapability task fencing', () => {
	it('preserves transactions that are not tied to a socket task', async () => {
		const persisted: SignalDataSet[] = []
		const keys = addTransactionCapability(
			makeSignalKeyStore(async data => {
				persisted.push(data)
			}),
			makeTestLogger(),
			{ maxCommitRetries: 1, delayBetweenTriesMs: 0 }
		)

		await keys.transaction(async () => {
			await keys.set({ session: { 'active.0': new Uint8Array([1]) } })
		}, 'active.0')

		expect(persisted).toEqual([{ session: { 'active.0': new Uint8Array([1]) } }])
	})

	it('does not commit a transaction after its socket generation is invalidated', async () => {
		let releaseWork: (() => void) | undefined
		let transactionReady: (() => void) | undefined
		const workGate = new Promise<void>(resolve => {
			releaseWork = resolve
		})
		const ready = new Promise<void>(resolve => {
			transactionReady = resolve
		})
		const persisted: SignalDataSet[] = []
		const guard = makeSocketTaskGuard()
		const keys = addTransactionCapability(
			makeSignalKeyStore(async data => {
				persisted.push(data)
			}),
			makeTestLogger(),
			{ maxCommitRetries: 1, delayBetweenTriesMs: 0 },
			() => guard.getCurrentSignal()
		)
		const task = guard.run(() =>
			keys.transaction(async () => {
				await keys.set({ session: { 'old.0': new Uint8Array([1]) } })
				transactionReady?.()
				await workGate
			}, 'old.0')
		)

		await ready
		guard.invalidate()
		releaseWork?.()

		await expect(task).rejects.toBeInstanceOf(StaleSocketTaskError)
		expect(persisted).toEqual([])
	})

	it('rejects a stale direct write while it is waiting in the key queue', async () => {
		let releaseFirstWrite: (() => void) | undefined
		let firstWriteStarted: (() => void) | undefined
		const firstWriteGate = new Promise<void>(resolve => {
			releaseFirstWrite = resolve
		})
		const started = new Promise<void>(resolve => {
			firstWriteStarted = resolve
		})
		const persisted: SignalDataSet[] = []
		const store = makeSignalKeyStore(async data => {
			persisted.push(data)
			if (persisted.length === 1) {
				firstWriteStarted?.()
				await firstWriteGate
			}
		})
		const guard = makeSocketTaskGuard()
		const keys = addTransactionCapability(
			store,
			makeTestLogger(),
			{ maxCommitRetries: 1, delayBetweenTriesMs: 0 },
			() => guard.getCurrentSignal()
		)
		const activeWrite = keys.set({ session: { 'active.0': new Uint8Array([1]) } })

		await started
		const staleWrite = guard.run(() => keys.set({ session: { 'stale.0': new Uint8Array([2]) } }))
		guard.invalidate()
		releaseFirstWrite?.()

		await activeWrite
		await expect(staleWrite).rejects.toBeInstanceOf(StaleSocketTaskError)
		expect(persisted).toHaveLength(1)
		expect(persisted[0]).toEqual({ session: { 'active.0': new Uint8Array([1]) } })
	})
})
