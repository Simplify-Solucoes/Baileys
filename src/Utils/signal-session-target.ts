export type SignalSessionTargetRepository = {
	jidToSignalProtocolAddress: (jid: string) => string
	lidMapping: {
		getKnownLIDForPN: (jid: string) => Promise<string | null>
	}
}

export type SignalSessionTarget = {
	sessionId: string
	usedLidMapping: boolean
}

export async function resolveSignalSessionTarget(
	repository: SignalSessionTargetRepository,
	jid: string
): Promise<SignalSessionTarget> {
	const knownLid = await repository.lidMapping.getKnownLIDForPN(jid)
	return {
		sessionId: repository.jidToSignalProtocolAddress(knownLid || jid),
		usedLidMapping: Boolean(knownLid)
	}
}
