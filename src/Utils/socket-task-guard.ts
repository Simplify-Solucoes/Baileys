import { AsyncLocalStorage } from 'async_hooks'

export const STALE_SOCKET_TASK_ERROR_CODE = 'ERR_STALE_SOCKET_TASK'

export class StaleSocketTaskError extends Error {
	readonly code = STALE_SOCKET_TASK_ERROR_CODE

	constructor() {
		super('Socket task belongs to an inactive generation')
		this.name = 'StaleSocketTaskError'
	}
}

export const isStaleSocketTaskError = (error: unknown): error is StaleSocketTaskError => {
	if (error instanceof StaleSocketTaskError) {
		return true
	}

	return typeof error === 'object' && error !== null && 'code' in error && error.code === STALE_SOCKET_TASK_ERROR_CODE
}

export const assertSocketTaskActive = (signal: AbortSignal | undefined): void => {
	if (!signal?.aborted) {
		return
	}

	throw signal.reason instanceof Error ? signal.reason : new StaleSocketTaskError()
}

export const makeSocketTaskGuard = () => {
	const taskStorage = new AsyncLocalStorage<AbortSignal>()
	const generationController = new AbortController()

	return {
		run<T>(work: () => Promise<T> | T): Promise<T> {
			return taskStorage.run(generationController.signal, async () => {
				assertSocketTaskActive(generationController.signal)
				return work()
			})
		},
		getCurrentSignal(): AbortSignal | undefined {
			return taskStorage.getStore()
		},
		runUntracked<T>(work: () => T): T {
			return taskStorage.exit(work)
		},
		isCurrentTaskActive(): boolean {
			return !generationController.signal.aborted && !taskStorage.getStore()?.aborted
		},
		isGenerationActive(): boolean {
			return !generationController.signal.aborted
		},
		invalidate(): void {
			if (!generationController.signal.aborted) {
				generationController.abort(new StaleSocketTaskError())
			}
		}
	}
}

export type SocketTaskGuard = ReturnType<typeof makeSocketTaskGuard>
