export type NodeProcessingTimeoutDependencies = {
	onUnexpectedError: (error: Error) => void
	onTimeout: (error: Error) => void
}

export async function processNodeWithTimeout<T>(
	task: Promise<T>,
	description: string,
	timeoutMs: number | undefined,
	dependencies: NodeProcessingTimeoutDependencies
): Promise<boolean> {
	let timeout: ReturnType<typeof setTimeout> | undefined
	let timedOut = false
	try {
		if (typeof timeoutMs !== 'number' || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
			await task
			return false
		}

		await Promise.race([
			task,
			new Promise<never>((_, reject) => {
				timeout = setTimeout(() => {
					timedOut = true
					reject(new Error(`${description} processing timed out`))
				}, timeoutMs)
			})
		])
		return false
	} catch (error) {
		const normalizedError = error instanceof Error ? error : new Error(String(error))
		if (timedOut) {
			dependencies.onTimeout(normalizedError)
			return true
		}

		dependencies.onUnexpectedError(normalizedError)
		return false
	} finally {
		if (timeout) {
			clearTimeout(timeout)
		}
	}
}
