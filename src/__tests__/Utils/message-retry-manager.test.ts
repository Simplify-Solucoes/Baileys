import { jest } from '@jest/globals'
import type { ILogger } from '../../Utils/logger'
import { MessageRetryManager, RetryReason } from '../../Utils/message-retry-manager'

function createLogger() {
	const warn = jest.fn<ILogger['warn']>()
	const logger: ILogger = {
		level: 'silent',
		child: () => logger,
		trace: () => undefined,
		debug: () => undefined,
		info: () => undefined,
		warn,
		error: () => undefined
	}

	return { logger, warn }
}

describe('MessageRetryManager', () => {
	it.each([RetryReason.SignalErrorInvalidMessage, RetryReason.SignalErrorBadMac])(
		'recreates a valid Signal session immediately for MAC error %s',
		errorCode => {
			const { logger } = createLogger()
			const manager = new MessageRetryManager(logger, 5)

			expect(manager.shouldRecreateSession('contact-device', true, errorCode)).toEqual({
				reason: `MAC error (code ${errorCode}: ${RetryReason[errorCode]}), immediate session recreation`,
				recreate: true
			})
		}
	)

	it('emits structured MAC diagnostics without the contact identifier', () => {
		const { logger, warn } = createLogger()
		const manager = new MessageRetryManager(logger, 5)

		manager.shouldRecreateSession('private-contact-identifier', true, RetryReason.SignalErrorBadMac)

		expect(warn).toHaveBeenCalledWith(
			{
				event: 'whatsapp_signal_mac_error',
				retryErrorCode: RetryReason.SignalErrorBadMac,
				retryErrorName: 'SignalErrorBadMac'
			},
			'MAC error detected, forcing immediate Signal session recreation'
		)
		expect(JSON.stringify(warn.mock.calls)).not.toContain('private-contact-identifier')
	})

	it('parses only supported retry error codes', () => {
		const { logger } = createLogger()
		const manager = new MessageRetryManager(logger, 5)

		expect(manager.parseRetryErrorCode('7')).toBe(RetryReason.SignalErrorBadMac)
		expect(manager.parseRetryErrorCode('not-a-number')).toBeUndefined()
		expect(manager.parseRetryErrorCode(undefined)).toBeUndefined()
	})
})
