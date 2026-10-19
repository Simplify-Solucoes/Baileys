import { jest } from '@jest/globals'
import { AsyncLocalStorage } from 'async_hooks'
import { processNodeWithTimeout } from '../../Utils/process-node-with-timeout'
import { assertSocketTaskActive, makeSocketTaskGuard, StaleSocketTaskError } from '../../Utils/socket-task-guard'

const createDeferred = () => {
	let resolvePromise: (() => void) | undefined
	const promise = new Promise<void>(resolve => {
		resolvePromise = resolve
	})

	return {
		promise,
		resolve: () => resolvePromise?.()
	}
}

describe('socket task guard', () => {
	it('rejects late tasks before entering async storage', async () => {
		const guard = makeSocketTaskGuard()
		guard.invalidate()
		const run = jest.spyOn(AsyncLocalStorage.prototype, 'run')
		const work = jest.fn(async () => {})
		try {
			await expect(guard.run(work)).rejects.toBeInstanceOf(StaleSocketTaskError)
			expect(work).not.toHaveBeenCalled()
			expect(run).not.toHaveBeenCalled()
		} finally {
			run.mockRestore()
		}
	})

	it('keeps storage instances bounded across invalidated generations', async () => {
		const run = jest.spyOn(AsyncLocalStorage.prototype, 'run')
		try {
			for (let generation = 0; generation < 100; generation++) {
				const guard = makeSocketTaskGuard()
				await guard.run(async () => {})
				await guard.runUntracked(async () => guard.invalidate())
			}

			expect(new Set(run.mock.contexts).size).toBe(1)
		} finally {
			run.mockRestore()
		}
	})

	it('untracks only its own generation while preserving nested guards', async () => {
		const first = makeSocketTaskGuard()
		const second = makeSocketTaskGuard()
		await first.run(async () => {
			const firstSignal = first.getCurrentSignal()
			expect(firstSignal).toBeDefined()
			expect(second.getCurrentSignal()).toBeUndefined()
			await second.run(async () => {
				const secondSignal = second.getCurrentSignal()
				expect(secondSignal).toBeDefined()
				expect(first.getCurrentSignal()).toBe(firstSignal)
				await first.runUntracked(async () => {
					await Promise.resolve()
					expect(first.getCurrentSignal()).toBeUndefined()
					expect(second.getCurrentSignal()).toBe(secondSignal)
				})
				expect(first.getCurrentSignal()).toBe(firstSignal)
			})
			expect(second.getCurrentSignal()).toBeUndefined()
		})
	})

	it('preserves invalidation in pending work while a new generation runs', async () => {
		const first = makeSocketTaskGuard()
		const second = makeSocketTaskGuard()
		const deferred = createDeferred()
		const pending = first.run(async () => {
			await deferred.promise
			assertSocketTaskActive(first.getCurrentSignal())
		})
		await first.runUntracked(async () => first.invalidate())
		await second.run(async () => {
			expect(second.getCurrentSignal()?.aborted).toBe(false)
			expect(first.getCurrentSignal()).toBeUndefined()
			deferred.resolve()
			await expect(pending).rejects.toBeInstanceOf(StaleSocketTaskError)
		})
	})

	it('blocks effects when a timed out task completes after invalidation', async () => {
		jest.useFakeTimers()
		try {
			const deferred = createDeferred()
			const guard = makeSocketTaskGuard()
			const effect = jest.fn()
			const task = guard.run(async () => {
				await deferred.promise
				assertSocketTaskActive(guard.getCurrentSignal())
				effect()
			})
			const result = processNodeWithTimeout(task, 'inbound message node', 100, {
				onUnexpectedError: jest.fn(),
				onTimeout: () => guard.invalidate()
			})

			await jest.advanceTimersByTimeAsync(100)
			await expect(result).resolves.toBe(true)

			deferred.resolve()
			await expect(task).rejects.toBeInstanceOf(StaleSocketTaskError)
			expect(effect).not.toHaveBeenCalled()
		} finally {
			jest.useRealTimers()
		}
	})

	it('does not attach the inactive signal to untracked lifecycle work', () => {
		const guard = makeSocketTaskGuard()

		guard.invalidate()

		expect(guard.getCurrentSignal()).toBeUndefined()
		expect(guard.isCurrentTaskActive()).toBe(false)
		expect(() => assertSocketTaskActive(guard.getCurrentSignal())).not.toThrow()
	})

	it('allows lifecycle cleanup to leave an invalidated task context', async () => {
		const guard = makeSocketTaskGuard()
		const cleanup = jest.fn()

		await guard.run(() => {
			guard.invalidate()
			return guard.runUntracked(async () => {
				expect(guard.getCurrentSignal()).toBeUndefined()
				await Promise.resolve()
				expect(guard.getCurrentSignal()).toBeUndefined()
				cleanup()
			})
		})

		expect(cleanup).toHaveBeenCalledTimes(1)
	})
})
