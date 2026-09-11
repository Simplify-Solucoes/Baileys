import { DEFAULT_CONNECTION_CONFIG, DEFAULT_INBOUND_NODE_PROCESSING_TIMEOUT_MS } from '../../Defaults'

describe('DEFAULT_CONNECTION_CONFIG', () => {
	it('allows two minutes for an inbound node to complete', () => {
		expect(DEFAULT_INBOUND_NODE_PROCESSING_TIMEOUT_MS).toBe(120_000)
		expect(DEFAULT_CONNECTION_CONFIG.inboundNodeProcessingTimeoutMs).toBe(DEFAULT_INBOUND_NODE_PROCESSING_TIMEOUT_MS)
	})
})
