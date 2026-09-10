import { jest } from '@jest/globals'
import { resolveSignalSessionTarget, type SignalSessionTargetRepository } from '../../Utils/signal-session-target'

function createRepository(knownLid: string | null) {
	const getKnownLIDForPN = jest.fn<(jid: string) => Promise<string | null>>().mockResolvedValue(knownLid)
	const jidToSignalProtocolAddress = jest.fn<(jid: string) => string>(jid => `signal:${jid}`)
	const repository: SignalSessionTargetRepository = {
		jidToSignalProtocolAddress,
		lidMapping: { getKnownLIDForPN }
	}

	return { repository, getKnownLIDForPN, jidToSignalProtocolAddress }
}

describe('resolveSignalSessionTarget', () => {
	it('uses the known LID when clearing a Signal session', async () => {
		const { repository, getKnownLIDForPN, jidToSignalProtocolAddress } = createRepository('known-lid@lid')

		await expect(resolveSignalSessionTarget(repository, 'contact@s.whatsapp.net')).resolves.toEqual({
			sessionId: 'signal:known-lid@lid',
			usedLidMapping: true
		})
		expect(getKnownLIDForPN).toHaveBeenCalledWith('contact@s.whatsapp.net')
		expect(jidToSignalProtocolAddress).toHaveBeenCalledWith('known-lid@lid')
	})

	it('falls back to the original JID when no LID mapping exists', async () => {
		const { repository, jidToSignalProtocolAddress } = createRepository(null)

		await expect(resolveSignalSessionTarget(repository, 'contact@s.whatsapp.net')).resolves.toEqual({
			sessionId: 'signal:contact@s.whatsapp.net',
			usedLidMapping: false
		})
		expect(jidToSignalProtocolAddress).toHaveBeenCalledWith('contact@s.whatsapp.net')
	})
})
