import { jest } from '@jest/globals'
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
