import { jest } from '@jest/globals'
import { processNodeWithTimeout } from '../../Utils/process-node-with-timeout'

describe('processNodeWithTimeout', () => {
	it('reports a stalled task as timed out', async () => {
		jest.useFakeTimers()
		try {
			const onUnexpectedError = jest.fn()
			const onTimeout = jest.fn()
			const result = processNodeWithTimeout(new Promise<void>(() => undefined), 'inbound message node', 100, {
				onUnexpectedError,
				onTimeout
			})

			await jest.advanceTimersByTimeAsync(100)

			await expect(result).resolves.toBe(true)
			expect(onTimeout).toHaveBeenCalledWith(
				expect.objectContaining({ message: 'inbound message node processing timed out' })
			)
			expect(onUnexpectedError).not.toHaveBeenCalled()
		} finally {
			jest.useRealTimers()
		}
	})

	it('reports a task rejection without classifying it as a timeout', async () => {
		const failure = new Error('controlled failure')
		const onUnexpectedError = jest.fn()
		const onTimeout = jest.fn()

		await expect(
			processNodeWithTimeout(Promise.reject(failure), 'inbound message node', 100, {
				onUnexpectedError,
				onTimeout
			})
		).resolves.toBe(false)
		expect(onUnexpectedError).toHaveBeenCalledWith(failure)
		expect(onTimeout).not.toHaveBeenCalled()
	})

	it('clears the timeout after the task completes', async () => {
		jest.useFakeTimers()
		try {
			const onUnexpectedError = jest.fn()
			const onTimeout = jest.fn()

			await expect(
				processNodeWithTimeout(Promise.resolve(), 'inbound message node', 100, {
					onUnexpectedError,
					onTimeout
				})
			).resolves.toBe(false)
			await jest.advanceTimersByTimeAsync(100)

			expect(onUnexpectedError).not.toHaveBeenCalled()
			expect(onTimeout).not.toHaveBeenCalled()
		} finally {
			jest.useRealTimers()
		}
	})
})
