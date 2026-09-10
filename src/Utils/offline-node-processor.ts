import type { BinaryNode } from '../WABinary'
import { processNodeWithTimeout } from './process-node-with-timeout'

export type MessageType = 'message' | 'call' | 'receipt' | 'notification'

export const isOfflineNode = (node: BinaryNode): boolean => node.attrs.offline === '1'

type OfflineNode = {
	type: MessageType
	node: BinaryNode
}

export type OfflineNodeProcessorDeps = {
	isWsOpen: () => boolean
	onUnexpectedError: (error: Error, msg: string) => void
	yieldToEventLoop: () => Promise<void>
	itemTimeoutMs?: number
	onItemTimeout?: (error: Error, type: MessageType, node: BinaryNode) => void
}

/**
 * Creates a processor for offline stanza nodes that:
 * - Queues nodes for sequential processing
 * - Yields to the event loop periodically to avoid blocking
 * - Catches handler errors to prevent the processing loop from crashing
 */
export function makeOfflineNodeProcessor(
	nodeProcessorMap: Map<MessageType, (node: BinaryNode) => Promise<void>>,
	deps: OfflineNodeProcessorDeps,
	batchSize = 10
) {
	const nodes: OfflineNode[] = []
	let isProcessing = false

	const enqueue = (type: MessageType, node: BinaryNode) => {
		nodes.push({ type, node })

		if (isProcessing) {
			return
		}

		isProcessing = true

		const promise = async () => {
			let processedInBatch = 0

			while (nodes.length && deps.isWsOpen()) {
				const { type, node } = nodes.shift()!

				const nodeProcessor = nodeProcessorMap.get(type)

				if (!nodeProcessor) {
					deps.onUnexpectedError(new Error(`unknown offline node type: ${type}`), 'processing offline node')
					continue
				}

				const timedOut = await processNodeWithTimeout(nodeProcessor(node), `offline ${type} node`, deps.itemTimeoutMs, {
					onUnexpectedError: error => deps.onUnexpectedError(error, `processing offline ${type}`),
					onTimeout: error => deps.onItemTimeout?.(error, type, node)
				})
				if (timedOut) {
					break
				}

				processedInBatch++

				// Yield to event loop after processing a batch
				// This prevents blocking the event loop for too long when there are many offline nodes
				if (processedInBatch >= batchSize) {
					processedInBatch = 0
					await deps.yieldToEventLoop()
				}
			}

			isProcessing = false
		}

		promise().catch(error => deps.onUnexpectedError(error, 'processing offline nodes'))
	}

	return { enqueue }
}
