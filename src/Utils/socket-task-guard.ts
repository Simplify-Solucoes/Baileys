import { AsyncLocalStorage } from 'async_hooks'

// Keep storage lifetime independent of socket churn; maps belong only to their async resources.
const taskStorage = new AsyncLocalStorage<ReadonlyMap<AbortController, AbortSignal>>()

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
	const generationController = new AbortController()

	return {
		async run<T>(work: () => Promise<T> | T): Promise<T> {
			assertSocketTaskActive(generationController.signal)
			const contexts = new Map(taskStorage.getStore())
			contexts.set(generationController, generationController.signal)
			return taskStorage.run(contexts, async () => work())
		},
		getCurrentSignal(): AbortSignal | undefined {
			return taskStorage.getStore()?.get(generationController)
		},
		runUntracked<T>(work: () => T): T {
			const current = taskStorage.getStore()
			if (!current?.has(generationController)) {
				return work()
			}

			const contexts = new Map(current)
			contexts.delete(generationController)
			return taskStorage.run(contexts, work)
		},
		isCurrentTaskActive(): boolean {
			return !generationController.signal.aborted && !taskStorage.getStore()?.get(generationController)?.aborted
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
